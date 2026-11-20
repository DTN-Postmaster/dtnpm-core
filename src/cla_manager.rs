//! CLA manager for runtime CLA interaction, peer status tracking and connection management.

use crate::coordinator::ContactExecutionEndpoint;
use hardy_bpv7::eid::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Connection status of a remote CLA peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerConnectionStatus {
    Connected,
    Disconnected,
    Connecting,
}

/// Status details for a registered CLA peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatusInfo {
    pub address: String,
    pub status: PeerConnectionStatus,
    pub last_attempt_at: Option<String>,
}

fn now_iso() -> String {
    let now = OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| now.to_string())
}

type RegisteredTcpPeer = (Arc<hardy_tcpclv4::Tcpclv4>, SocketAddr);

#[derive(Clone)]
struct RegisteredContactPeer {
    callsign: String,
    node_id: Option<NodeId>,
    endpoint: Arc<dyn ContactExecutionEndpoint>,
}

/// Thread-safe manager for configured CLAs and their peers.
#[derive(Clone, Default)]
pub struct ClaManager {
    tcp_peers: Arc<RwLock<Vec<RegisteredTcpPeer>>>,
    contact_peers: Arc<RwLock<Vec<RegisteredContactPeer>>>,
    statuses: Arc<RwLock<HashMap<String, PeerStatusInfo>>>,
}

impl ClaManager {
    /// Creates a new empty CLA manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tcp_peers: Arc::new(RwLock::new(Vec::new())),
            contact_peers: Arc::new(RwLock::new(Vec::new())),
            statuses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a TCPCLv4 instance with a remote peer socket address.
    pub async fn register_tcp_peer(&self, cla: Arc<hardy_tcpclv4::Tcpclv4>, addr: SocketAddr) {
        let mut guard = self.tcp_peers.write().await;
        guard.push((cla, addr));

        let key = addr.to_string();
        let mut st = self.statuses.write().await;
        st.entry(key.clone()).or_insert_with(|| PeerStatusInfo {
            address: key,
            status: PeerConnectionStatus::Disconnected,
            last_attempt_at: None,
        });
    }

    /// Registers a [`ContactExecutionEndpoint`] (such as Mercury Connected ARQ) for a peer callsign.
    pub async fn register_contact_peer(
        &self,
        callsign: String,
        node_id: Option<NodeId>,
        endpoint: Arc<dyn ContactExecutionEndpoint>,
    ) {
        let normalized = callsign.trim().to_uppercase();
        let mut guard = self.contact_peers.write().await;
        guard.push(RegisteredContactPeer {
            callsign: normalized.clone(),
            node_id,
            endpoint,
        });

        let mut st = self.statuses.write().await;
        st.entry(normalized.clone())
            .or_insert_with(|| PeerStatusInfo {
                address: normalized,
                status: PeerConnectionStatus::Disconnected,
                last_attempt_at: None,
            });
    }

    /// Updates the connection status for a peer identified by key string.
    async fn set_status_by_key(&self, key: &str, status: PeerConnectionStatus) {
        let mut st = self.statuses.write().await;
        st.insert(
            key.to_string(),
            PeerStatusInfo {
                address: key.to_string(),
                status,
                last_attempt_at: Some(now_iso()),
            },
        );
    }

    /// Updates the connection status for a TCPCL peer.
    pub async fn set_peer_status(&self, addr: SocketAddr, status: PeerConnectionStatus) {
        self.set_status_by_key(&addr.to_string(), status).await;
    }

    /// Checks if a peer is currently marked as connected.
    pub async fn is_peer_connected(&self, addr: &SocketAddr) -> bool {
        let st = self.statuses.read().await;
        st.get(&addr.to_string())
            .map(|info| info.status == PeerConnectionStatus::Connected)
            .unwrap_or(false)
    }

    /// Returns a list of all tracked peer statuses.
    pub async fn list_peer_statuses(&self) -> Vec<PeerStatusInfo> {
        let st = self.statuses.read().await;
        st.values().cloned().collect()
    }

    /// Initiates an active connection attempt to a specified peer address or callsign.
    pub async fn connect_peer(&self, peer_str: &str) -> anyhow::Result<()> {
        let target_str = peer_str.trim();

        let matched_tcp = {
            let guard = self.tcp_peers.read().await;
            guard
                .iter()
                .find(|(_, addr)| {
                    addr.to_string() == target_str
                        || target_str
                            .parse::<SocketAddr>()
                            .map(|a| a == *addr)
                            .unwrap_or(false)
                })
                .cloned()
        };

        if let Some((cla, addr)) = matched_tcp {
            info!("Connection attempt initiated for TCPCL peer {}", addr);
            self.set_peer_status(addr, PeerConnectionStatus::Connecting)
                .await;

            match cla.connect(&addr).await {
                Ok(()) => {
                    info!("TCPCL connection to {} established successfully", addr);
                    self.set_peer_status(addr, PeerConnectionStatus::Connected)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!("TCPCL connection to {} failed: {}", addr, e);
                    self.set_peer_status(addr, PeerConnectionStatus::Disconnected)
                        .await;
                    anyhow::bail!("TCPCL connection to {} failed: {e}", addr);
                }
            }
        }

        let matched_contact = {
            let guard = self.contact_peers.read().await;
            guard
                .iter()
                .find(|p| {
                    p.callsign.eq_ignore_ascii_case(target_str)
                        || p.node_id
                            .as_ref()
                            .is_some_and(|n| n.to_string() == target_str)
                })
                .cloned()
        };

        if let Some(peer) = matched_contact {
            info!(
                "Connection attempt initiated for contact peer {}",
                peer.callsign
            );
            self.set_status_by_key(&peer.callsign, PeerConnectionStatus::Connecting)
                .await;

            match peer
                .endpoint
                .start_contact(&peer.callsign, peer.node_id.as_ref())
                .await
            {
                Ok(()) => {
                    info!(
                        "Contact connection to {} established successfully",
                        peer.callsign
                    );
                    self.set_status_by_key(&peer.callsign, PeerConnectionStatus::Connected)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!("Contact connection to {} failed: {}", peer.callsign, e);
                    self.set_status_by_key(&peer.callsign, PeerConnectionStatus::Disconnected)
                        .await;
                    anyhow::bail!("Connection to {} failed: {e}", peer.callsign);
                }
            }
        }

        anyhow::bail!("No configured CLA adapter found for peer '{}'", target_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardy_bpa::async_trait;

    struct MockEndpoint {
        succeed: bool,
    }

    #[async_trait]
    impl ContactExecutionEndpoint for MockEndpoint {
        async fn start_contact(
            &self,
            _callsign: &str,
            _node_id: Option<&NodeId>,
        ) -> Result<(), String> {
            if self.succeed {
                Ok(())
            } else {
                Err("modem timeout".to_string())
            }
        }

        async fn end_contact(&self, _callsign: &str) -> Result<(), String> {
            Ok(())
        }

        async fn is_active(&self) -> bool {
            self.succeed
        }
    }

    #[tokio::test]
    async fn test_register_and_connect_contact_peer() {
        let manager = ClaManager::new();
        let endpoint = Arc::new(MockEndpoint { succeed: true });
        let node_id: NodeId = "dtn://va3nb/".parse().unwrap();

        manager
            .register_contact_peer("va3nb".to_string(), Some(node_id), endpoint)
            .await;

        manager.connect_peer("VA3NB").await.unwrap();

        let statuses = manager.list_peer_statuses().await;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].address, "VA3NB");
        assert_eq!(statuses[0].status, PeerConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn test_connect_contact_peer_failure_resets_status() {
        let manager = ClaManager::new();
        let endpoint = Arc::new(MockEndpoint { succeed: false });

        manager
            .register_contact_peer("F4TEST".to_string(), None, endpoint)
            .await;

        let err = manager.connect_peer("F4TEST").await.unwrap_err();
        assert!(err.to_string().contains("modem timeout"));

        let statuses = manager.list_peer_statuses().await;
        assert_eq!(statuses[0].status, PeerConnectionStatus::Disconnected);
    }

    #[tokio::test]
    async fn test_connect_unknown_peer_errors() {
        let manager = ClaManager::new();
        let err = manager.connect_peer("UNKNOWN").await.unwrap_err();
        assert!(
            err.to_string()
                .contains("No configured CLA adapter found for peer 'UNKNOWN'")
        );
    }
}
