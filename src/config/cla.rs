//! Convergence Layer Adapter configuration for Hamradio BPA.

use core::num::NonZeroU64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::SocketAddr;

/// Canonical automatic APRS transport aliases for all built-in CLA families.
pub const BUILTIN_CLA_TRANSPORT_ALIASES: &[&str] = &["TCPCL", "LTP", "HQFBP", "MERCURY", "FILE"];

/// Returns the automatic canonical APRS transport alias for a CLA protocol type
/// (e.g. `"tcpclv4"` -> `"TCPCL"`, `"ltp"` -> `"LTP"`, `"file-cla"` -> `"FILE"`).
#[must_use]
pub fn auto_cla_transport_alias(cla_type: &str) -> Option<&'static str> {
    match cla_type.trim().to_ascii_lowercase().as_str() {
        "tcpclv4" | "tcpcl" => Some("TCPCL"),
        "ltp" => Some("LTP"),
        "hqfbp" => Some("HQFBP"),
        "mercury-arq" | "mercury" => Some("MERCURY"),
        "file-cla" | "file" => Some("FILE"),
        _ => None,
    }
}

/// Computes the canonical, sorted, deduplicated uppercase alias list for a CLA,
/// combining the automatic transport tag for `cla_type` with explicit `configured` aliases.
#[must_use]
pub fn canonical_cla_aliases(cla_type: &str, configured: &[String]) -> Vec<String> {
    let mut set = BTreeSet::new();
    if let Some(auto_alias) = auto_cla_transport_alias(cla_type) {
        set.insert(auto_alias.to_string());
    }
    for raw in configured {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_ascii_uppercase());
        }
    }
    set.into_iter().collect()
}

/// CLA entry in configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaConfig {
    /// Human-readable unique name for this CLA instance.
    pub name: String,
    /// Specific CLA type and configuration.
    #[serde(flatten)]
    pub cla_type: ClaType,
    /// Optional egress policy name.
    #[serde(default)]
    pub policy: Option<String>,
    /// Optional contact schedule for this CLA.
    #[serde(default)]
    pub schedule: Option<ScheduleConfig>,
    /// Optional APRS-style CLA/band aliases (e.g. `["VHF", "2M"]`, `["QO100"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

impl ClaConfig {
    /// Returns the effective canonical uppercase aliases for this CLA
    /// (automatic transport tag plus configured `aliases`).
    #[must_use]
    pub fn effective_aliases(&self) -> Vec<String> {
        canonical_cla_aliases(self.cla_type.type_name(), &self.aliases)
    }
}

/// Supported CLA protocol engines.
///
/// Built-in node-level/core variants (`tcpclv4`, `mercury-arq`) have typed
/// configurations here, while external/extension CLAs (such as `ltp`, `hqfbp`,
/// `file-cla`, or future hardware adapters) deserialize into [`ClaType::Other`]
/// without creating cyclic dependencies on external CLA crates.
#[derive(Debug, Clone)]
pub enum ClaType {
    /// TCPCL v4 convergence layer (RFC 9174).
    TcpClv4(Tcpclv4HamConfig),

    /// Mercury connected ARQ convergence layer.
    MercuryArq(MercuryArqHamConfig),

    /// Generic plugin CLA configuration keyed by `type` (e.g. `ltp`, `hqfbp`).
    Other {
        cla_type: String,
        config: serde_json::Value,
    },
}

impl ClaType {
    /// Returns the canonical protocol type identifier (e.g. `"tcpclv4"`, `"ltp"`, `"hqfbp"`).
    #[must_use]
    pub fn type_name(&self) -> &str {
        match self {
            Self::TcpClv4(_) => "tcpclv4",
            Self::MercuryArq(_) => "mercury-arq",
            Self::Other { cla_type, .. } => cla_type.as_str(),
        }
    }

    /// Constructs a [`ClaType::Other`] variant from any serializable CLA configuration.
    pub fn custom<T: Serialize>(
        cla_type: impl Into<String>,
        config: &T,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self::Other {
            cla_type: cla_type.into(),
            config: serde_json::to_value(config)?,
        })
    }

    /// Attempts to deserialize a [`ClaType::Other`] payload as a concrete typed CLA config
    /// if its `type` matches `expected_type` (or returns `Ok(None)` otherwise).
    pub fn parse_as<T: serde::de::DeserializeOwned>(
        &self,
        expected_type: &str,
    ) -> Result<Option<T>, serde_json::Error> {
        match self {
            Self::Other { cla_type, config }
                if cla_type.trim().eq_ignore_ascii_case(expected_type.trim()) =>
            {
                serde_json::from_value(config.clone()).map(Some)
            }
            _ => Ok(None),
        }
    }
}

impl Serialize for ClaType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (tag, value) = match self {
            Self::TcpClv4(cfg) => ("tcpclv4", serde_json::to_value(cfg)),
            Self::MercuryArq(cfg) => ("mercury-arq", serde_json::to_value(cfg)),
            Self::Other { cla_type, config } => (cla_type.as_str(), Ok(config.clone())),
        };
        let value = value.map_err(serde::ser::Error::custom)?;
        let mut map = match value {
            serde_json::Value::Object(m) => m,
            serde_json::Value::Null => serde_json::Map::new(),
            other => {
                let mut m = serde_json::Map::new();
                m.insert("value".to_string(), other);
                m
            }
        };
        map.insert(
            "type".to_string(),
            serde_json::Value::String(tag.to_string()),
        );
        map.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ClaType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut map = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let raw_type = map
            .remove("type")
            .and_then(|v| v.as_str().map(str::to_string))
            .ok_or_else(|| serde::de::Error::missing_field("type"))?;
        match raw_type.trim().to_ascii_lowercase().as_str() {
            "tcpclv4" | "tcpcl" => serde_json::from_value(serde_json::Value::Object(map))
                .map(Self::TcpClv4)
                .map_err(serde::de::Error::custom),
            "mercury-arq" | "mercury" => serde_json::from_value(serde_json::Value::Object(map))
                .map(Self::MercuryArq)
                .map_err(serde::de::Error::custom),
            _ => Ok(Self::Other {
                cla_type: raw_type,
                config: serde_json::Value::Object(map),
            }),
        }
    }
}

/// Simplified Hamradio-friendly configuration for TCPCLv4.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Tcpclv4HamConfig {
    /// Single listening socket address (e.g. `"[::]:4556"`).
    pub address: Option<SocketAddr>,

    /// Multiple listening addresses.
    pub listeners: Option<Vec<SocketAddr>>,

    /// Whether TLS is mandatory. Disabled by default for amateur radio compliance (Hamnet / 44Net).
    #[serde(alias = "require_tls", alias = "require-tls")]
    pub require_tls: Option<bool>,

    /// Outbound peer socket addresses to connect to (e.g. `["44.27.131.233:4556"]`).
    pub peers: Option<Vec<String>>,

    /// Largest acceptable single-segment payload in bytes.
    pub segment_mru: Option<NonZeroU64>,

    /// Largest acceptable total bundle transfer in bytes.
    pub transfer_mru: Option<NonZeroU64>,
}

fn default_mercury_control() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8300))
}

fn default_mercury_data() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8301))
}

fn default_bandwidth() -> u32 {
    2300
}

/// Configuration for Mercury Connected ARQ CLA.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct MercuryArqHamConfig {
    /// Local amateur radio callsign (inherits from root config if not set).
    pub my_callsign: Option<String>,
    /// Control TCP port address (default: 127.0.0.1:8300).
    pub control_addr: SocketAddr,
    /// Data TCP port address (default: 127.0.0.1:8301).
    pub data_addr: SocketAddr,
    /// ARQ bandwidth in Hz (default: 2300).
    pub bandwidth: u32,
    /// Idle disconnect timeout.
    #[serde(with = "crate::duration::serde_duration_opt", default)]
    pub idle_timeout: Option<std::time::Duration>,
    /// Grace period for in-flight bundle drain upon window expiration (default: 30s).
    #[serde(with = "crate::duration::serde_duration_opt", default)]
    pub grace_period: Option<std::time::Duration>,
    /// Connect handshake timeout (default: 30s).
    #[serde(with = "crate::duration::serde_duration_opt", default)]
    pub connect_timeout: Option<std::time::Duration>,
    /// Configured peers and contact schedules.
    pub peers: Vec<MercuryPeerHamConfig>,
}

impl Default for MercuryArqHamConfig {
    fn default() -> Self {
        Self {
            my_callsign: None,
            control_addr: default_mercury_control(),
            data_addr: default_mercury_data(),
            bandwidth: default_bandwidth(),
            idle_timeout: None,
            grace_period: Some(std::time::Duration::from_secs(30)),
            connect_timeout: Some(std::time::Duration::from_secs(30)),
            peers: Vec::new(),
        }
    }
}

/// Configuration entry for a peer in Mercury Connected ARQ mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MercuryPeerHamConfig {
    /// Remote callsign.
    pub callsign: String,
    /// Remote node EID. If omitted, defaults to `dtn://<callsign>/`.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Optional scheduled contact plan.
    #[serde(default)]
    pub schedule: Option<ScheduleConfig>,
}

impl MercuryPeerHamConfig {
    /// Returns the effective Node ID string for this peer.
    #[must_use]
    pub fn effective_node_id(&self) -> String {
        if let Some(ref nid) = self.node_id {
            nid.clone()
        } else {
            format!("dtn://{}/", self.callsign.to_lowercase())
        }
    }
}

/// Contact schedule configuration (recurring cron or one-shot).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum ScheduleConfig {
    #[serde(rename = "recurring", alias = "cron")]
    Recurring {
        cron: String,
        #[serde(with = "crate::duration::serde_duration")]
        duration: std::time::Duration,
    },
    #[serde(rename = "one-shot", alias = "oneshot")]
    OneShot {
        #[serde(default)]
        start: Option<String>,
        #[serde(default)]
        end: Option<String>,
    },
}
