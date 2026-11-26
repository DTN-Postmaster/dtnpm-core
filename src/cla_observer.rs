//! Transparent [`Cla`] and [`Sink`] wrapper observing neighbor peer
//! discovery (`add_peer` / `remove_peer`) without modifying Hardy BPA.

use core::num::NonZeroU64;
use std::sync::Arc;

use hardy_bpa::async_trait;
use hardy_bpa::cla::{Acceptance, Cla, ClaAddress, ForwardBundleResult, Result as ClaResult, Sink};
use hardy_bpa::stream::{Receiver, Segment};
use hardy_bpv7::bundle::Id;
use hardy_bpv7::eid::NodeId;

/// Observer notified when a CLA reports a neighbor peer coming up or going down.
pub trait PeerObserver: Send + Sync {
    /// Called when a CLA is registered with its configured aliases.
    fn on_cla_registered(&self, _cla_name: &str, _cla_type: &str, _aliases: &[String]) {}
    fn on_peer_up(&self, cla_name: &str, cla_type: &str, addr: &ClaAddress, node_ids: &[NodeId]);
    fn on_peer_down(&self, cla_name: &str, addr: &ClaAddress);
}

/// [`Cla`] wrapper delegating all operations to `inner` while wrapping its
/// [`Sink`] so `add_peer` and `remove_peer` notifications reach `observer`.
pub struct ObservedCla {
    cla_name: String,
    cla_type: String,
    inner: Arc<dyn Cla>,
    observer: Arc<dyn PeerObserver>,
}

impl ObservedCla {
    /// Wraps `inner` with peer-change observation for `cla_name` / `cla_type`.
    pub fn wrap(
        cla_name: impl Into<String>,
        cla_type: impl Into<String>,
        inner: Arc<dyn Cla>,
        observer: Arc<dyn PeerObserver>,
    ) -> Arc<dyn Cla> {
        Self::wrap_with_aliases(cla_name, cla_type, Vec::new(), inner, observer)
    }

    /// Wraps `inner` with peer-change observation and registers `aliases` for `cla_name`.
    pub fn wrap_with_aliases(
        cla_name: impl Into<String>,
        cla_type: impl Into<String>,
        aliases: Vec<String>,
        inner: Arc<dyn Cla>,
        observer: Arc<dyn PeerObserver>,
    ) -> Arc<dyn Cla> {
        let cla_name = cla_name.into();
        let cla_type = cla_type.into();
        observer.on_cla_registered(&cla_name, &cla_type, &aliases);
        Arc::new(Self {
            cla_name,
            cla_type,
            inner,
            observer,
        })
    }
}

#[async_trait]
impl Cla for ObservedCla {
    async fn on_register(
        &self,
        sink: Box<dyn Sink>,
        node_ids: &[NodeId],
        max_bundle_size: Option<NonZeroU64>,
    ) {
        let wrapped_sink = Box::new(ObservedClaSink {
            cla_name: self.cla_name.clone(),
            cla_type: self.cla_type.clone(),
            inner: sink,
            observer: self.observer.clone(),
        });
        self.inner
            .on_register(wrapped_sink, node_ids, max_bundle_size)
            .await;
    }

    async fn on_unregister(&self) {
        self.inner.on_unregister().await;
    }

    async fn forward(
        &self,
        lane: Option<u32>,
        cla_addr: &ClaAddress,
        bundle_id: &Id,
        total_len: u64,
        stream: &mut dyn Receiver<Segment>,
    ) -> ClaResult<ForwardBundleResult> {
        self.inner
            .forward(lane, cla_addr, bundle_id, total_len, stream)
            .await
    }
}

struct ObservedClaSink {
    cla_name: String,
    cla_type: String,
    inner: Box<dyn Sink>,
    observer: Arc<dyn PeerObserver>,
}

#[async_trait]
impl Sink for ObservedClaSink {
    async fn unregister(&self) {
        self.inner.unregister().await;
    }

    async fn dispatch(
        &self,
        peer_node: Option<&NodeId>,
        peer_addr: Option<&ClaAddress>,
        stream: &mut dyn Receiver<Segment>,
    ) -> ClaResult<Acceptance> {
        self.inner.dispatch(peer_node, peer_addr, stream).await
    }

    async fn add_peer(&self, cla_addr: ClaAddress, node_ids: &[NodeId]) -> ClaResult<bool> {
        let added = self.inner.add_peer(cla_addr.clone(), node_ids).await?;
        if added {
            self.observer
                .on_peer_up(&self.cla_name, &self.cla_type, &cla_addr, node_ids);
        }
        Ok(added)
    }

    async fn remove_peer(&self, cla_addr: &ClaAddress) -> ClaResult<bool> {
        let removed = self.inner.remove_peer(cla_addr).await?;
        self.observer.on_peer_down(&self.cla_name, cla_addr);
        Ok(removed)
    }

    async fn transfer_outcome(
        &self,
        bundle_id: &Id,
        outcome: hardy_bpa::cla::TransferOutcome,
    ) -> ClaResult<()> {
        self.inner.transfer_outcome(bundle_id, outcome).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockSink {
        accept_peer: bool,
    }

    #[async_trait]
    impl Sink for MockSink {
        async fn unregister(&self) {}

        async fn dispatch(
            &self,
            _peer_node: Option<&NodeId>,
            _peer_addr: Option<&ClaAddress>,
            _stream: &mut dyn Receiver<Segment>,
        ) -> ClaResult<Acceptance> {
            Ok(Acceptance::Accepted)
        }

        async fn add_peer(&self, _cla_addr: ClaAddress, _node_ids: &[NodeId]) -> ClaResult<bool> {
            Ok(self.accept_peer)
        }

        async fn remove_peer(&self, _cla_addr: &ClaAddress) -> ClaResult<bool> {
            Ok(true)
        }

        async fn transfer_outcome(
            &self,
            _bundle_id: &Id,
            _outcome: hardy_bpa::cla::TransferOutcome,
        ) -> ClaResult<()> {
            Ok(())
        }
    }

    struct CountingObserver {
        peer_up_calls: AtomicUsize,
    }

    impl PeerObserver for CountingObserver {
        fn on_peer_up(
            &self,
            _cla_name: &str,
            _cla_type: &str,
            _addr: &ClaAddress,
            _node_ids: &[NodeId],
        ) {
            self.peer_up_calls.fetch_add(1, Ordering::SeqCst);
        }

        fn on_peer_down(&self, _cla_name: &str, _addr: &ClaAddress) {}
    }

    #[tokio::test]
    async fn add_peer_notifies_observer_only_when_accepted() {
        let addr = ClaAddress::Private(hardy_bpa::Bytes::from_static(b"/tmp/inbox"));
        let node_id: NodeId = "dtn://peer/".parse().unwrap();

        let observer_rejected = Arc::new(CountingObserver {
            peer_up_calls: AtomicUsize::new(0),
        });
        let sink_rejected = ObservedClaSink {
            cla_name: "file-1".to_string(),
            cla_type: "file-cla".to_string(),
            inner: Box::new(MockSink { accept_peer: false }),
            observer: observer_rejected.clone(),
        };
        assert!(
            !sink_rejected
                .add_peer(addr.clone(), std::slice::from_ref(&node_id))
                .await
                .unwrap()
        );
        assert_eq!(observer_rejected.peer_up_calls.load(Ordering::SeqCst), 0);

        let observer_accepted = Arc::new(CountingObserver {
            peer_up_calls: AtomicUsize::new(0),
        });
        let sink_accepted = ObservedClaSink {
            cla_name: "file-1".to_string(),
            cla_type: "file-cla".to_string(),
            inner: Box::new(MockSink { accept_peer: true }),
            observer: observer_accepted.clone(),
        };
        assert!(
            sink_accepted
                .add_peer(addr, std::slice::from_ref(&node_id))
                .await
                .unwrap()
        );
        assert_eq!(observer_accepted.peer_up_calls.load(Ordering::SeqCst), 1);
    }
}
