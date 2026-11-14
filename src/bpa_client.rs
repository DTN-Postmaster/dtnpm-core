//! Unified BPA client abstraction across in-process, gRPC, and mock transports.

use hardy_async::async_trait;
use hardy_bpa::bpa::BpaRegistration;
use hardy_bpa::cla::{Cla, ClaInit};
use hardy_bpa::policy::FlowControllerFactory;
use hardy_bpa::routing::{self, RoutingAgent};
use hardy_bpa::services::{self, Application, Service};
use hardy_bpv7::eid::{Eid, NodeId, Service as ServiceId};
use std::sync::Arc;

/// Transport-agnostic handle for registering services, CLAs, and routing agents
/// with a Hardy Bundle Processing Agent (in-process, over gRPC, or mocked in tests).
#[async_trait]
pub trait BpaClient: BpaRegistration + Send + Sync {
    /// Returns a human-readable identifier for this transport (e.g. `"local"`, `"grpc"`, `"mock"`).
    fn transport_name(&self) -> &str;

    /// Returns this handle as a dynamically dispatched [`BpaRegistration`].
    fn as_registration(self: Arc<Self>) -> Arc<dyn BpaRegistration>;
}

/// In-process BPA client delegating directly to a local [`BpaRegistration`] (e.g. `hardy_bpa::bpa::Bpa`).
#[derive(Clone)]
pub struct LocalBpaClient {
    inner: Arc<dyn BpaRegistration>,
}

impl LocalBpaClient {
    /// Wraps an in-process BPA implementation as a [`BpaClient`].
    pub fn new(inner: Arc<dyn BpaRegistration>) -> Self {
        Self { inner }
    }

    /// Returns a clone of the underlying [`BpaRegistration`] trait object.
    #[must_use]
    pub fn inner(&self) -> Arc<dyn BpaRegistration> {
        self.inner.clone()
    }
}

#[async_trait]
impl BpaRegistration for LocalBpaClient {
    async fn register_cla(
        &self,
        name: String,
        cla: Arc<dyn Cla>,
        policy: Option<Arc<dyn FlowControllerFactory>>,
        init: ClaInit,
    ) -> hardy_bpa::cla::Result<Vec<NodeId>> {
        self.inner.register_cla(name, cla, policy, init).await
    }

    async fn register_service(
        &self,
        service_id: ServiceId,
        service: Arc<dyn Service>,
    ) -> services::Result<Eid> {
        self.inner.register_service(service_id, service).await
    }

    async fn register_application(
        &self,
        service_id: ServiceId,
        application: Arc<dyn Application>,
    ) -> services::Result<Eid> {
        self.inner
            .register_application(service_id, application)
            .await
    }

    async fn register_dynamic_service(&self, service: Arc<dyn Service>) -> services::Result<Eid> {
        self.inner.register_dynamic_service(service).await
    }

    async fn register_dynamic_application(
        &self,
        application: Arc<dyn Application>,
    ) -> services::Result<Eid> {
        self.inner.register_dynamic_application(application).await
    }

    async fn register_routing_agent(
        &self,
        name: String,
        agent: Arc<dyn RoutingAgent>,
    ) -> routing::Result<Vec<NodeId>> {
        self.inner.register_routing_agent(name, agent).await
    }
}

#[async_trait]
impl BpaClient for LocalBpaClient {
    fn transport_name(&self) -> &str {
        "local"
    }

    fn as_registration(self: Arc<Self>) -> Arc<dyn BpaRegistration> {
        self.inner.clone()
    }
}

/// Remote BPA client communicating over gRPC via [`hardy_proto::client::RemoteBpa`].
#[cfg(feature = "transport-grpc")]
pub struct GrpcBpaClient {
    endpoint: String,
    remote: hardy_proto::client::RemoteBpa,
    _bridge_guard: Option<crate::iam::grpc_guard::GrpcBridgeGuard>,
}

#[cfg(feature = "transport-grpc")]
impl GrpcBpaClient {
    /// Creates a new gRPC BPA client targeting `grpc_addr` (e.g. `"http://127.0.0.1:50051"`),
    /// automatically honoring `DTN_HDY_TOKEN` and `DTN_HDY_SOCKET` if set.
    pub fn new(grpc_addr: impl Into<String>) -> Self {
        Self::with_auth(grpc_addr, None, None)
    }

    /// Creates a new gRPC BPA client with explicit optional Bearer token and Unix socket path.
    pub fn with_auth(
        grpc_addr: impl Into<String>,
        token: Option<&str>,
        socket_path: Option<&str>,
    ) -> Self {
        let raw = grpc_addr.into();
        match crate::iam::grpc_guard::prepare_grpc_endpoint(&raw, token, socket_path) {
            Ok((effective_endpoint, guard)) => {
                let remote = hardy_proto::client::RemoteBpa::new(effective_endpoint.clone());
                Self {
                    endpoint: raw,
                    remote,
                    _bridge_guard: guard,
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to prepare authenticated gRPC bridge for {raw}: {e}; using direct endpoint"
                );
                let remote = hardy_proto::client::RemoteBpa::new(raw.clone());
                Self {
                    endpoint: raw,
                    remote,
                    _bridge_guard: None,
                }
            }
        }
    }

    /// Returns the configured gRPC endpoint string.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[cfg(feature = "transport-grpc")]
#[async_trait]
impl BpaRegistration for GrpcBpaClient {
    async fn register_cla(
        &self,
        name: String,
        cla: Arc<dyn Cla>,
        policy: Option<Arc<dyn FlowControllerFactory>>,
        init: ClaInit,
    ) -> hardy_bpa::cla::Result<Vec<NodeId>> {
        self.remote.register_cla(name, cla, policy, init).await
    }

    async fn register_service(
        &self,
        service_id: ServiceId,
        service: Arc<dyn Service>,
    ) -> services::Result<Eid> {
        self.remote.register_service(service_id, service).await
    }

    async fn register_application(
        &self,
        service_id: ServiceId,
        application: Arc<dyn Application>,
    ) -> services::Result<Eid> {
        self.remote
            .register_application(service_id, application)
            .await
    }

    async fn register_dynamic_service(&self, service: Arc<dyn Service>) -> services::Result<Eid> {
        self.remote.register_dynamic_service(service).await
    }

    async fn register_dynamic_application(
        &self,
        application: Arc<dyn Application>,
    ) -> services::Result<Eid> {
        self.remote.register_dynamic_application(application).await
    }

    async fn register_routing_agent(
        &self,
        name: String,
        agent: Arc<dyn RoutingAgent>,
    ) -> routing::Result<Vec<NodeId>> {
        self.remote.register_routing_agent(name, agent).await
    }
}

#[cfg(feature = "transport-grpc")]
#[async_trait]
impl BpaClient for GrpcBpaClient {
    fn transport_name(&self) -> &str {
        "grpc"
    }

    fn as_registration(self: Arc<Self>) -> Arc<dyn BpaRegistration> {
        self
    }
}
