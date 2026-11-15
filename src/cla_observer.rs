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
        Arc::new(Self {
            cla_name: cla_name.into(),
            cla_type: cla_type.into(),
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
        self.observer
            .on_peer_up(&self.cla_name, &self.cla_type, &cla_addr, node_ids);
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
