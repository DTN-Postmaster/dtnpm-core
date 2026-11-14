//! In-memory mock BPA implementation for standalone unit and integration tests.

use crate::bpa_client::BpaClient;
use bytes::Bytes;
use hardy_async::async_trait;
use hardy_bpa::bpa::BpaRegistration;
use hardy_bpa::cla::{self, Acceptance, Cla, ClaAddress, ClaInit};
use hardy_bpa::policy::FlowControllerFactory;
use hardy_bpa::routing::{self, RouteAction, RoutingAgent, RoutingSink};
use hardy_bpa::services::{
    self, Application, ApplicationSink, SendOptions, Service, ServiceSink, StatusNotify,
};
use hardy_bpa::stream::{Receiver, Segment, concat_stream};
use hardy_bpv7::bundle::Id;
use hardy_bpv7::builder::Builder;
use hardy_bpv7::creation_timestamp::CreationTimestamp;
use hardy_bpv7::eid::{DtnNodeId, Eid, IpnNodeId, NodeId, Service as ServiceId};
use hardy_bpv7::status_report::ReasonCode;
use hardy_eid_patterns::EidPattern;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;

/// A bundle captured by [`MockBpa`] when originated by a service or dispatched by a CLA.
#[derive(Debug, Clone)]
pub struct CapturedBundle {
    pub id: Id,
    pub source: Eid,
    pub destination: Eid,
    pub raw: Bytes,
}

enum RegisteredTarget {
    Service(Arc<dyn Service>),
    Application(Arc<dyn Application>),
}

struct MockBpaInner {
    ipn: Option<IpnNodeId>,
    dtn: Option<DtnNodeId>,
    targets: RwLock<HashMap<Eid, RegisteredTarget>>,
    clas: RwLock<HashMap<String, Arc<dyn Cla>>>,
    routes: RwLock<Vec<(String, EidPattern, RouteAction, u32)>>,
    sent_bundles: RwLock<Vec<CapturedBundle>>,
    dynamic_seq: AtomicU32,
}

impl MockBpaInner {
    fn resolve_eid(&self, service_id: &ServiceId) -> services::Result<Eid> {
        match service_id {
            ServiceId::Ipn(n) => Ok(Eid::Ipn {
                fqnn: self.ipn.ok_or(services::Error::Disconnected)?,
                service_number: *n,
            }),
            ServiceId::Dtn(name) => Ok(Eid::Dtn {
                node_name: self.dtn.clone().ok_or(services::Error::Disconnected)?,
                service_name: name.clone(),
            }),
        }
    }

    fn node_ids(&self) -> Vec<NodeId> {
        let mut out = Vec::new();
        if let Some(ipn) = self.ipn {
            out.push(NodeId::Ipn(ipn));
        }
        if let Some(ref dtn) = self.dtn {
            out.push(NodeId::Dtn(dtn.clone()));
        }
        out
    }

    async fn record_and_maybe_deliver(&self, raw: Bytes) -> Result<Id, String> {
        let parsed = hardy_bpv7::parse::parse(raw.clone()).map_err(|e| e.to_string())?;
        let bundle = parsed.bundle;

        let id = bundle.primary.id.clone();
        let source = bundle.primary.id.source.clone();
        let destination = bundle.primary.destination.clone();
        let expiry = OffsetDateTime::now_utc()
            + time::Duration::try_from(bundle.primary.lifetime)
                .unwrap_or(time::Duration::seconds(3600));
        let ack_requested = bundle.primary.flags.app_ack_requested;
        let total_len = raw.len() as u64;

        {
            let mut log = self.sent_bundles.write().unwrap_or_else(|e| e.into_inner());
            log.push(CapturedBundle {
                id: id.clone(),
                source,
                destination: destination.clone(),
                raw: raw.clone(),
            });
        }

        let target = {
            let map = self.targets.read().unwrap_or_else(|e| e.into_inner());
            map.get(&destination).map(|entry| match entry {
                RegisteredTarget::Service(s) => RegisteredTarget::Service(s.clone()),
                RegisteredTarget::Application(a) => RegisteredTarget::Application(a.clone()),
            })
        };

        if let Some(target) = target {
            match target {
                RegisteredTarget::Service(svc) => {
                    let mut stream = raw;
                    svc.on_deliver(&id, expiry, total_len, &mut stream)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                RegisteredTarget::Application(app) => {
                    let payload = extract_payload(&bundle, &raw)?;
                    let payload_len = payload.len() as u64;
                    let mut stream = payload;
                    app.on_deliver(&id, expiry, ack_requested, payload_len, &mut stream)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }

        Ok(id)
    }
}

fn extract_payload(bundle: &hardy_bpv7::bundle::Bundle, raw: &[u8]) -> Result<Bytes, String> {
    if let Some(block) = bundle.blocks.get(&1)
        && let Some(slice) = block.payload(raw)
    {
        return Ok(Bytes::copy_from_slice(slice));
    }
    Err("bundle has no payload block".to_string())
}

/// Lightweight in-memory mock BPA for testing CLAs, services, and web modules without
/// starting a full Hardy BPA storage/network runtime.
#[derive(Clone)]
pub struct MockBpa {
    inner: Arc<MockBpaInner>,
}

impl Default for MockBpa {
    fn default() -> Self {
        Self::new("dtn://mock/")
    }
}

impl MockBpa {
    /// Creates a `MockBpa` configured with the supplied node ID (e.g. `"dtn://test/"` or `"ipn:1.0"`).
    pub fn new(node_id: &str) -> Self {
        let parsed: NodeId = node_id.parse().expect("valid mock NodeId");
        let (ipn, dtn) = match parsed {
            NodeId::Ipn(ipn) => (Some(ipn), None),
            NodeId::Dtn(dtn) => (None, Some(dtn)),
            NodeId::LocalNode => panic!("LocalNode is not valid for MockBpa::new"),
        };
        Self {
            inner: Arc::new(MockBpaInner {
                ipn,
                dtn,
                targets: RwLock::new(HashMap::new()),
                clas: RwLock::new(HashMap::new()),
                routes: RwLock::new(Vec::new()),
                sent_bundles: RwLock::new(Vec::new()),
                dynamic_seq: AtomicU32::new(100),
            }),
        }
    }

    /// Creates a `MockBpa` with both a DTN node ID and an IPN node ID.
    pub fn with_node_ids(dtn: Option<&str>, ipn: Option<&str>) -> Self {
        let dtn = dtn.map(|s| match s.parse::<NodeId>().expect("valid dtn NodeId") {
            NodeId::Dtn(n) => n,
            _ => panic!("expected dtn NodeId"),
        });
        let ipn = ipn.map(|s| match s.parse::<NodeId>().expect("valid ipn NodeId") {
            NodeId::Ipn(n) => n,
            _ => panic!("expected ipn NodeId"),
        });
        Self {
            inner: Arc::new(MockBpaInner {
                ipn,
                dtn,
                targets: RwLock::new(HashMap::new()),
                clas: RwLock::new(HashMap::new()),
                routes: RwLock::new(Vec::new()),
                sent_bundles: RwLock::new(Vec::new()),
                dynamic_seq: AtomicU32::new(100),
            }),
        }
    }

    /// Delivers a serialized BPv7 bundle into the mock BPA (recording it and invoking
    /// any matching registered local service/application).
    pub async fn deliver_raw(&self, raw: Bytes) -> anyhow::Result<Id> {
        self.inner
            .record_and_maybe_deliver(raw)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Builds and delivers a simple BPv7 bundle with the given payload to `destination`.
    pub async fn deliver_payload(
        &self,
        source: &str,
        destination: &str,
        payload: &[u8],
    ) -> anyhow::Result<Id> {
        let src: Eid = source.parse()?;
        let dst: Eid = destination.parse()?;
        let builder = Builder::new(src, dst).with_payload(std::borrow::Cow::Borrowed(payload));
        let (_bundle, raw) = builder.build(CreationTimestamp::now())?;
        self.deliver_raw(Bytes::from(raw)).await
    }

    /// Returns a snapshot of all bundles sent or dispatched through this `MockBpa`.
    #[must_use]
    pub fn sent_bundles(&self) -> Vec<CapturedBundle> {
        self.inner
            .sent_bundles
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Clears captured sent bundles.
    pub fn clear_sent_bundles(&self) {
        self.inner
            .sent_bundles
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Returns registered service/application EIDs.
    #[must_use]
    pub fn registered_eids(&self) -> Vec<Eid> {
        self.inner
            .targets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Returns registered CLA names.
    #[must_use]
    pub fn registered_clas(&self) -> Vec<String> {
        self.inner
            .clas
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Returns configured routes `(agent_name, pattern, action, priority)`.
    #[must_use]
    pub fn registered_routes(&self) -> Vec<(String, EidPattern, RouteAction, u32)> {
        self.inner
            .routes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

struct MockServiceSink {
    eid: Eid,
    inner: Arc<MockBpaInner>,
}

#[async_trait]
impl ServiceSink for MockServiceSink {
    async fn unregister(&self) {
        let removed = self
            .inner
            .targets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.eid);
        if let Some(RegisteredTarget::Service(svc)) = removed {
            svc.on_unregister().await;
        }
    }

    async fn send(&self, stream: &mut dyn Receiver<Segment>) -> services::Result<Id> {
        let raw = concat_stream(stream, usize::MAX)
            .await
            .map_err(|_| services::Error::Disconnected)?;
        self.inner
            .record_and_maybe_deliver(raw)
            .await
            .map_err(|_| services::Error::Disconnected)
    }
}

struct MockAppSink {
    eid: Eid,
    inner: Arc<MockBpaInner>,
}

#[async_trait]
impl ApplicationSink for MockAppSink {
    async fn unregister(&self) {
        let removed = self
            .inner
            .targets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.eid);
        if let Some(RegisteredTarget::Application(app)) = removed {
            app.on_unregister().await;
        }
    }

    async fn send(
        &self,
        destination: Eid,
        data: Bytes,
        lifetime: core::time::Duration,
        _options: Option<SendOptions>,
    ) -> services::Result<Id> {
        let builder = Builder::new(self.eid.clone(), destination)
            .with_lifetime(lifetime)
            .with_payload(std::borrow::Cow::Borrowed(&data));
        let (_bundle, raw) = builder
            .build(CreationTimestamp::now())
            .map_err(|_| services::Error::Disconnected)?;
        self.inner
            .record_and_maybe_deliver(Bytes::from(raw))
            .await
            .map_err(|_| services::Error::Disconnected)
    }

    async fn send_streamed(
        &self,
        destination: Eid,
        _total_len: u64,
        stream: &mut dyn Receiver<Segment>,
        lifetime: core::time::Duration,
        options: Option<SendOptions>,
    ) -> services::Result<Id> {
        let data = concat_stream(stream, usize::MAX)
            .await
            .map_err(|_| services::Error::Disconnected)?;
        self.send(destination, data, lifetime, options).await
    }
}

struct MockClaSink {
    name: String,
    inner: Arc<MockBpaInner>,
}

#[async_trait]
impl cla::Sink for MockClaSink {
    async fn unregister(&self) {
        let removed = self
            .inner
            .clas
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.name);
        if let Some(cla) = removed {
            cla.on_unregister().await;
        }
    }

    async fn dispatch(
        &self,
        _peer_node: Option<&NodeId>,
        _peer_addr: Option<&ClaAddress>,
        stream: &mut dyn Receiver<Segment>,
    ) -> cla::Result<Acceptance> {
        let raw = concat_stream(stream, usize::MAX)
            .await
            .map_err(|_| cla::Error::Disconnected)?;
        match self.inner.record_and_maybe_deliver(raw).await {
            Ok(_) => Ok(Acceptance::Accepted),
            Err(_) => Ok(Acceptance::Refused),
        }
    }

    async fn add_peer(&self, _cla_addr: ClaAddress, _node_ids: &[NodeId]) -> cla::Result<bool> {
        Ok(true)
    }

    async fn remove_peer(&self, _cla_addr: &ClaAddress) -> cla::Result<bool> {
        Ok(true)
    }

    async fn transfer_outcome(
        &self,
        _bundle_id: &Id,
        _outcome: cla::TransferOutcome,
    ) -> cla::Result<()> {
        Ok(())
    }
}

struct MockRoutingSink {
    name: String,
    inner: Arc<MockBpaInner>,
}

#[async_trait]
impl RoutingSink for MockRoutingSink {
    async fn unregister(&self) {
        let mut routes = self.inner.routes.write().unwrap_or_else(|e| e.into_inner());
        routes.retain(|(src, _, _, _)| src != &self.name);
    }

    async fn add_route(
        &self,
        pattern: EidPattern,
        action: RouteAction,
        priority: u32,
    ) -> routing::Result<bool> {
        let mut routes = self.inner.routes.write().unwrap_or_else(|e| e.into_inner());
        let exists = routes
            .iter()
            .any(|(s, p, a, pr)| s == &self.name && p == &pattern && a == &action && *pr == priority);
        if exists {
            return Ok(false);
        }
        routes.push((self.name.clone(), pattern, action, priority));
        Ok(true)
    }

    async fn remove_route(
        &self,
        pattern: &EidPattern,
        action: &RouteAction,
        priority: u32,
    ) -> routing::Result<bool> {
        let mut routes = self.inner.routes.write().unwrap_or_else(|e| e.into_inner());
        let before = routes.len();
        routes.retain(|(s, p, a, pr)| {
            !(s == &self.name && p == pattern && a == action && *pr == priority)
        });
        Ok(routes.len() != before)
    }
}

#[async_trait]
impl BpaRegistration for MockBpa {
    async fn register_cla(
        &self,
        name: String,
        cla: Arc<dyn Cla>,
        _policy: Option<Arc<dyn FlowControllerFactory>>,
        _init: ClaInit,
    ) -> cla::Result<Vec<NodeId>> {
        let node_ids = self.inner.node_ids();
        self.inner
            .clas
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.clone(), cla.clone());
        let sink = Box::new(MockClaSink {
            name,
            inner: self.inner.clone(),
        });
        cla.on_register(sink, &node_ids, None).await;
        Ok(node_ids)
    }

    async fn register_service(
        &self,
        service_id: ServiceId,
        service: Arc<dyn Service>,
    ) -> services::Result<Eid> {
        let eid = self.inner.resolve_eid(&service_id)?;
        self.inner
            .targets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(eid.clone(), RegisteredTarget::Service(service.clone()));
        let sink = Box::new(MockServiceSink {
            eid: eid.clone(),
            inner: self.inner.clone(),
        });
        service.on_register(&eid, sink).await;
        Ok(eid)
    }

    async fn register_application(
        &self,
        service_id: ServiceId,
        application: Arc<dyn Application>,
    ) -> services::Result<Eid> {
        let eid = self.inner.resolve_eid(&service_id)?;
        self.inner
            .targets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(eid.clone(), RegisteredTarget::Application(application.clone()));
        let sink = Box::new(MockAppSink {
            eid: eid.clone(),
            inner: self.inner.clone(),
        });
        application.on_register(&eid, sink).await;
        Ok(eid)
    }

    async fn register_dynamic_service(&self, service: Arc<dyn Service>) -> services::Result<Eid> {
        let seq = self.inner.dynamic_seq.fetch_add(1, Ordering::Relaxed);
        let service_id = if self.inner.dtn.is_some() {
            ServiceId::Dtn(format!("svc-{seq}").into())
        } else {
            ServiceId::Ipn(seq)
        };
        self.register_service(service_id, service).await
    }

    async fn register_dynamic_application(
        &self,
        application: Arc<dyn Application>,
    ) -> services::Result<Eid> {
        let seq = self.inner.dynamic_seq.fetch_add(1, Ordering::Relaxed);
        let service_id = if self.inner.dtn.is_some() {
            ServiceId::Dtn(format!("app-{seq}").into())
        } else {
            ServiceId::Ipn(seq)
        };
        self.register_application(service_id, application).await
    }

    async fn register_routing_agent(
        &self,
        name: String,
        agent: Arc<dyn RoutingAgent>,
    ) -> routing::Result<Vec<NodeId>> {
        let node_ids = self.inner.node_ids();
        let sink = Box::new(MockRoutingSink {
            name,
            inner: self.inner.clone(),
        });
        agent.on_register(sink, &node_ids).await;
        Ok(node_ids)
    }
}

#[async_trait]
impl BpaClient for MockBpa {
    fn transport_name(&self) -> &str {
        "mock"
    }

    fn as_registration(self: Arc<Self>) -> Arc<dyn BpaRegistration> {
        self
    }
}

// Keep unused imports silent if future status notification tests use them
#[allow(dead_code)]
fn _status_notify_marker(_: StatusNotify, _: ReasonCode, _: OffsetDateTime) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct EchoMockService {
        delivered: Mutex<Vec<Id>>,
    }

    #[async_trait]
    impl Service for EchoMockService {
        async fn on_register(&self, _endpoint: &Eid, _sink: Box<dyn ServiceSink>) {}
        async fn on_unregister(&self) {}
        async fn on_deliver(
            &self,
            bundle_id: &Id,
            _expiry: OffsetDateTime,
            _total_len: u64,
            stream: &mut dyn Receiver<Segment>,
        ) -> services::Result<()> {
            let _ = concat_stream(stream, usize::MAX).await;
            self.delivered
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(bundle_id.clone());
            Ok(())
        }
        async fn on_status_notify(
            &self,
            _bundle_id: &Id,
            _from: &Eid,
            _kind: StatusNotify,
            _reason: ReasonCode,
            _timestamp: Option<OffsetDateTime>,
        ) {
        }
    }

    #[tokio::test]
    async fn test_mock_bpa_service_registration_and_delivery() {
        let bpa = MockBpa::new("dtn://f4klo/");
        let svc = Arc::new(EchoMockService {
            delivered: Mutex::new(Vec::new()),
        });

        let eid = bpa
            .register_service(ServiceId::Dtn("chat".into()), svc.clone())
            .await
            .unwrap();
        assert_eq!(eid.to_string(), "dtn://f4klo/chat");

        bpa.deliver_payload("dtn://f6xyz/chat", "dtn://f4klo/chat", b"73 de F6XYZ")
            .await
            .unwrap();

        assert_eq!(svc.delivered.lock().unwrap().len(), 1);
        assert_eq!(bpa.sent_bundles().len(), 1);
    }
}
