//! Configuration for the Hamradio BPA node.

pub mod cla;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

fn default_node_id() -> String {
    "dtn://n0call/".to_string()
}

fn default_grpc_addr() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 50051))
}

/// Root configuration structure for `dtnpm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct HamConfig {
    /// Administrative radio callsign (e.g. `STATA` or `F4JXQ`).
    /// If set and `node_id` is default, `node_id` defaults to `dtn://<callsign>/`.
    #[serde(default)]
    pub callsign: Option<String>,

    /// Administrative Node EID (e.g. `dtn://f4jxq/` or `ipn:1.0`).
    #[serde(default = "default_node_id")]
    pub node_id: String,

    /// Additional administrative EIDs for this node.
    pub admin_endpoints: Vec<String>,

    /// Bundle storage settings (SQLite database).
    pub storage: StorageConfig,

    /// Application service settings (Chat, Files, and storage quota).
    #[serde(default)]
    pub application: ApplicationConfig,

    /// Local gRPC application server settings.
    pub grpc: GrpcConfig,

    /// Web dashboard and REST API server settings (optional).
    pub web: Option<WebConfig>,

    /// Configured Convergence Layer Adapters (TCPCLv4, LTP, HQFBP, Mercury ARQ, File CLA).
    pub clas: Vec<cla::ClaConfig>,

    /// Static routing definitions.
    pub routes: Vec<RouteConfig>,

    /// Optional OPA/Rego routing policy overrides (`dtnpm-mod-rego-routing`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rego_routing: Option<RegoRoutingYamlConfig>,

    /// SenML telemetry and dashboard configuration.
    #[serde(default)]
    pub senml: Option<SenmlConfig>,

    /// RFC 9171 ingress validation policy toggles.
    #[serde(default)]
    pub rfc9171_validity: Option<Rfc9171ValidityConfig>,

    /// Identity, authentication, and Policy-Based Access Control (PBAC) configuration.
    #[serde(default)]
    pub auth: AuthConfig,

    /// Optional native TLS configuration for the HTTP/REST server.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Optional filesystem path this configuration was loaded from.
    #[serde(skip)]
    pub config_path: Option<PathBuf>,
}

impl Default for HamConfig {
    fn default() -> Self {
        Self {
            callsign: None,
            node_id: default_node_id(),
            admin_endpoints: Vec::new(),
            storage: StorageConfig::default(),
            application: ApplicationConfig::default(),
            grpc: GrpcConfig::default(),
            web: None,
            clas: Vec::new(),
            routes: Vec::new(),
            senml: None,
            rego_routing: None,
            rfc9171_validity: Some(Rfc9171ValidityConfig::default()),
            auth: AuthConfig::default(),
            tls: TlsConfig::default(),
            config_path: None,
        }
    }
}

/// RFC 9171 ingress validation toggles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Rfc9171ValidityConfig {
    /// Require CRC or BIB on the primary block.
    /// In amateur radio context, defaults to `Some(false)` for out-of-the-box interoperability
    /// with implementations (e.g. dtn-android-messenger / dtn7-rs) that do not generate a primary block CRC.
    pub primary_block_integrity: Option<bool>,

    /// Require a Bundle Age block when the creation time has no clock.
    pub bundle_age_required: Option<bool>,
}

impl Default for Rfc9171ValidityConfig {
    fn default() -> Self {
        Self {
            primary_block_integrity: Some(false),
            bundle_age_required: Some(false),
        }
    }
}

/// Storage options for bundles and metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct StorageConfig {
    /// Directory for pending bundle payloads and SQLite database. Defaults to `~/.local/share/dtnpm`.
    pub data_dir: Option<PathBuf>,

    /// Path to SQLite database file. Kept for backwards compatibility.
    pub sqlite_path: Option<PathBuf>,

    /// Run with in-memory volatile storage (useful for testing and ephemeral nodes).
    pub in_memory: bool,
}

impl StorageConfig {
    /// Returns the effective base directory for storage.
    pub fn effective_data_dir(&self) -> PathBuf {
        if let Some(ref dir) = self.data_dir {
            dir.clone()
        } else if let Some(ref db) = self.sqlite_path {
            db.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
        } else if let Some(base_dirs) = directories::BaseDirs::new() {
            base_dirs.data_local_dir().join("dtnpm")
        } else {
            PathBuf::from("./data")
        }
    }

    /// Returns the effective SQLite database file path.
    pub fn effective_db_path(&self) -> PathBuf {
        if let Some(ref db) = self.sqlite_path {
            db.clone()
        } else {
            self.effective_data_dir().join("bundles.db")
        }
    }

    /// Returns the effective directory for storing bundle payloads.
    pub fn effective_payload_dir(&self) -> PathBuf {
        self.effective_data_dir().join("payloads")
    }
}

/// Application service settings (e.g. Chat, Files, and storage quota).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct ApplicationConfig {
    /// Storage quota policy.
    pub quota: QuotaConfig,
}

/// Application storage quota configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct QuotaConfig {
    /// Maximum disk space allowed for application data (chat DB + files payload dir).
    /// Accepts numbers (e.g. `314572800`) or human-readable strings (e.g. `"300MB"`, `"300MiB"`, `"1GB"`).
    /// Defaults to 300 MB (314,572,800 bytes).
    #[serde(
        deserialize_with = "deserialize_byte_size",
        serialize_with = "serialize_byte_size"
    )]
    pub max_storage: u64,
}

pub const DEFAULT_APP_MAX_STORAGE_BYTES: u64 = 300 * 1024 * 1024; // 300 MB

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_storage: DEFAULT_APP_MAX_STORAGE_BYTES,
        }
    }
}

/// Parses human-readable byte sizes (e.g. `"300MB"`, `"300MiB"`, `"1GB"` or numeric `"1024"`).
pub fn parse_byte_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty byte size".to_string());
    }
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }
    let num_end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num_str, unit_str) = s.split_at(num_end);
    let val: f64 = num_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid number '{num_str}': {e}"))?;
    let unit = unit_str.trim().to_uppercase();
    let multiplier: f64 = match unit.as_str() {
        "" | "B" | "BYTES" => 1.0,
        "K" | "KB" | "KIB" => 1024.0,
        "M" | "MB" | "MIB" => 1024.0 * 1024.0,
        "G" | "GB" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "T" | "TB" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => return Err(format!("unknown byte unit '{other}'")),
    };
    Ok((val * multiplier) as u64)
}

fn deserialize_byte_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ByteSizeVisitor;

    impl<'de> serde::de::Visitor<'de> for ByteSizeVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte size string (e.g. '300MB', '500KB') or an integer")
        }

        fn visit_u64<E>(self, value: u64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            if value < 0 {
                return Err(E::custom("byte size cannot be negative"));
            }
            Ok(value as u64)
        }

        fn visit_str<E>(self, value: &str) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            parse_byte_size(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(ByteSizeVisitor)
}

fn serialize_byte_size<S>(val: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = *val;
    let s = if bytes > 0 && bytes.is_multiple_of(1024 * 1024 * 1024) {
        format!("{}GB", bytes / (1024 * 1024 * 1024))
    } else if bytes > 0 && bytes.is_multiple_of(1024 * 1024) {
        format!("{}MB", bytes / (1024 * 1024))
    } else if bytes > 0 && bytes.is_multiple_of(1024) {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{bytes}B")
    };
    serializer.serialize_str(&s)
}

/// gRPC application interface settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct GrpcConfig {
    /// Enable the gRPC application service (required for `dtnsend`, `dtnprint`, etc.).
    pub enabled: bool,

    /// Local address to bind the gRPC server.
    pub address: SocketAddr,

    /// Authentication and Unix Domain Socket settings for the gRPC server.
    #[serde(default)]
    pub auth: GrpcAuthConfig,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: default_grpc_addr(),
            auth: GrpcAuthConfig::default(),
        }
    }
}

/// Authentication operating mode for HTTP/Web access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// No authentication (open local station dashboard, default for backward compatibility).
    #[default]
    None,
    /// Delegate authentication to a trusted reverse proxy (SSOwat, Authelia, Authentik, Nginx).
    Proxy,
    /// Built-in local authentication using Argon2id users, HttpOnly sessions, and Bearer API tokens.
    Local,
}

impl AuthMode {
    /// Returns the lowercase canonical string representation (`"none"`, `"proxy"`, `"local"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Proxy => "proxy",
            Self::Local => "local",
        }
    }
}

fn default_proxy_header_user() -> String {
    "Remote-User".to_string()
}

fn default_proxy_header_groups() -> String {
    "Remote-Groups".to_string()
}

fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1/32".to_string(), "::1/128".to_string()]
}

/// Reverse-proxy SSO header configuration (`[auth.proxy]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct ProxyAuthConfig {
    /// Header carrying the authenticated username (e.g. `Remote-User`).
    #[serde(default = "default_proxy_header_user", alias = "header_user")]
    pub header_user: String,

    /// Header carrying comma-separated user groups (e.g. `Remote-Groups`).
    #[serde(default = "default_proxy_header_groups", alias = "header_groups")]
    pub header_groups: String,

    /// CIDR list of trusted reverse proxies allowed to supply identity headers.
    #[serde(default = "default_trusted_proxies", alias = "trusted_proxies")]
    pub trusted_proxies: Vec<String>,
}

impl Default for ProxyAuthConfig {
    fn default() -> Self {
        Self {
            header_user: default_proxy_header_user(),
            header_groups: default_proxy_header_groups(),
            trusted_proxies: default_trusted_proxies(),
        }
    }
}

fn default_admin_groups() -> Vec<String> {
    vec!["admins".to_string(), "dtn_admins".to_string()]
}

fn default_session_ttl() -> String {
    "24h".to_string()
}

/// Parses a human-readable duration string (e.g. `"24h"`, `"30m"`, `"3600s"`, or raw seconds).
#[must_use]
pub fn parse_duration_secs(s: &str) -> u64 {
    let trimmed = s.trim();
    if let Ok(secs) = trimmed.parse::<u64>() {
        return secs.max(1);
    }
    crate::duration::parse_duration(trimmed)
        .map(|d| d.as_secs().max(1))
        .unwrap_or(86_400)
}

/// Root IAM and PBAC configuration (`[auth]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct AuthConfig {
    /// Authentication mode (`none`, `proxy`, or `local`).
    pub mode: AuthMode,

    /// Explicit usernames mapped to the `Admin` role (primarily for `proxy` mode).
    #[serde(default, alias = "admin_users")]
    pub admin_users: Vec<String>,

    /// Explicit groups mapped to the `Admin` role (in `proxy` mode).
    #[serde(default = "default_admin_groups", alias = "admin_groups")]
    pub admin_groups: Vec<String>,

    /// Optional path to an external OPA Rego policy file overriding the embedded policy.
    #[serde(default, alias = "policy_path")]
    pub policy_path: Option<PathBuf>,

    /// Session time-to-live for `local` authentication cookies (e.g. `"24h"`).
    #[serde(default = "default_session_ttl", alias = "session_ttl")]
    pub session_ttl: String,

    /// Reverse-proxy SSO parameters when `mode = "proxy"`.
    #[serde(default)]
    pub proxy: ProxyAuthConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::None,
            admin_users: Vec::new(),
            admin_groups: default_admin_groups(),
            policy_path: None,
            session_ttl: default_session_ttl(),
            proxy: ProxyAuthConfig::default(),
        }
    }
}

fn default_operator_role() -> String {
    "Operator".to_string()
}

/// Static pre-shared API/gRPC token entry (`[[grpc.auth.tokens]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcTokenEntry {
    /// Human-readable service identifier (e.g. `"ltp-kiss-daemon"`).
    pub name: String,

    /// Secret Bearer token value.
    pub token: String,

    /// Role assigned to this token (`Admin` or `Operator`).
    #[serde(default = "default_operator_role")]
    pub role: String,
}

fn default_socket_mode() -> String {
    "0660".to_string()
}

/// Authentication and Unix Domain Socket settings for gRPC (`[grpc.auth]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct GrpcAuthConfig {
    /// Require Bearer token authentication on TCP gRPC connections.
    pub enabled: bool,

    /// Optional Unix Domain Socket path for local daemon-to-daemon gRPC access.
    #[serde(default, alias = "socket_path")]
    pub socket_path: Option<PathBuf>,

    /// Optional system group name for the Unix Domain Socket.
    #[serde(default, alias = "socket_group")]
    pub socket_group: Option<String>,

    /// Octal permissions mode string for the Unix Domain Socket (default `"0660"`).
    #[serde(default = "default_socket_mode", alias = "socket_mode")]
    pub socket_mode: String,

    /// Statically configured Bearer tokens for gRPC services/CLAs.
    #[serde(default)]
    pub tokens: Vec<GrpcTokenEntry>,
}

impl Default for GrpcAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: None,
            socket_group: None,
            socket_mode: default_socket_mode(),
            tokens: Vec::new(),
        }
    }
}

/// Optional native TLS configuration (`[tls]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct TlsConfig {
    /// Enable TLS termination directly in the embedded Axum web server.
    pub enabled: bool,

    /// Path to PEM-encoded certificate chain.
    #[serde(default, alias = "cert_path")]
    pub cert_path: Option<PathBuf>,

    /// Path to PEM-encoded private key.
    #[serde(default, alias = "key_path")]
    pub key_path: Option<PathBuf>,
}

fn default_web_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8088))
}

pub fn default_web_static_dir() -> PathBuf {
    if Path::new("web/dist").exists() {
        PathBuf::from("web/dist")
    } else if Path::new("ui/dist").exists() {
        PathBuf::from("ui/dist")
    } else if Path::new("../dtnpm-web-core/ui/dist").exists() {
        PathBuf::from("../dtnpm-web-core/ui/dist")
    } else if Path::new("dtnpm/web/dist").exists() {
        PathBuf::from("dtnpm/web/dist")
    } else if let Ok(exe) = std::env::current_exe() {
        let exe_dir = exe.parent().unwrap_or_else(|| Path::new("."));
        let candidate = exe_dir.join("web").join("dist");
        if candidate.exists() {
            return candidate;
        }
        if let Some(parent) = exe_dir.parent() {
            let candidate_parent = parent.join("web").join("dist");
            if candidate_parent.exists() {
                return candidate_parent;
            }
        }
        PathBuf::from("web/dist")
    } else {
        PathBuf::from("web/dist")
    }
}

/// Expands leading `~` to the user's home directory.
#[must_use]
pub fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~")
        && let Some(base) = directories::BaseDirs::new()
    {
        return base.home_dir().join(stripped);
    }
    path.to_path_buf()
}

/// Contracts `$HOME` into `~` for concise display in prompts.
#[must_use]
pub fn contract_tilde(path: &Path) -> String {
    if let Some(base) = directories::BaseDirs::new() {
        let home = base.home_dir();
        if let Ok(stripped) = path.strip_prefix(home) {
            return format!("~/{}", stripped.display());
        }
    }
    path.display().to_string()
}

/// Web dashboard and REST API interface settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct WebConfig {
    /// Local address to bind the web server (e.g. `127.0.0.1:8080`).
    #[serde(default = "default_web_addr")]
    pub address: SocketAddr,

    /// Directory containing static web assets (Vite dist).
    #[serde(
        default = "default_web_static_dir",
        alias = "web-dist",
        alias = "static_dir"
    )]
    pub static_dir: PathBuf,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            address: default_web_addr(),
            static_dir: default_web_static_dir(),
        }
    }
}

/// Static routing entry mapping an EID pattern to a CLA and next hop.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteConfig {
    /// EID pattern to match (e.g. `dtn://*/*` or `ipn:*.*`).
    pub pattern: String,

    /// Target CLA name.
    pub cla: String,

    /// Optional next hop address (e.g. `44.27.131.233:4556` or callsign).
    pub next_hop: Option<String>,

    /// Optional route action (`via` by default, or `forward-replicate` for Spray-and-Wait).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Configuration for the built-in ANSRVR group subscription & announcement service (`dtn://<node>/ansrvr`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct AnsrvrYamlConfig {
    /// Enable the built-in `/ansrvr` service (default `true`).
    pub enabled: bool,
    /// Local DTN service name (default `"ansrvr"`).
    pub service_name: String,
    /// Default subscription TTL in seconds (default `86400` = 24h).
    pub default_ttl_secs: u64,
    /// Maximum active groups tracked in SQLite (default `256`).
    pub max_groups: usize,
    /// Maximum active members per group (default `256`).
    pub max_members_per_group: usize,
    /// Maximum accepted incoming command/announcement payload size in bytes (default `4096`).
    pub max_payload_bytes: u64,
    /// Minimum interval in seconds between `CQ` announcements per sender (default `5`).
    pub cq_rate_limit_secs: u64,
}

impl Default for AnsrvrYamlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "ansrvr".to_string(),
            default_ttl_secs: 86_400,
            max_groups: 256,
            max_members_per_group: 256,
            max_payload_bytes: 4096,
            cq_rate_limit_secs: 5,
        }
    }
}

/// Optional OPA/Rego routing policy overrides in `HamConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RegoRoutingYamlConfig {
    /// Directory containing optional `dtn_constants.rego`, `helpers.rego`, `ingress.rego`, `egress.rego`, `routing.rego`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_dir: Option<PathBuf>,

    /// Inline override for `ingress.rego`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_ingress_rego: Option<String>,

    /// Inline override for `egress.rego`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_egress_rego: Option<String>,

    /// Inline override for `routing.rego` (`package dtn.routing`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_routing_rego: Option<String>,

    /// Enable recording Traceroute Extension Block (TREB) hops on transit bundles (default `false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_treb: Option<bool>,

    /// Additional node-level APRS aliases supported by this station.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_aliases: Vec<String>,

    /// APRS aliases explicitly trapped/dropped at ingress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trapped_aliases: Vec<String>,

    /// Built-in ANSRVR group subscription & announcement service settings.
    #[serde(default)]
    pub ansrvr: AnsrvrYamlConfig,
}

/// SenML telemetry configuration block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SenmlConfig {
    /// List of ordered dashboard metrics.
    #[serde(default)]
    pub metrics: Vec<DashboardMetricConfig>,
}

/// A configured telemetry metric card for the SenML dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DashboardMetricConfig {
    /// Full SenML metric name (e.g. `urn:dtn:node1:power/bus_voltage`).
    pub name: String,

    /// Optional human-readable display alias/label (e.g. `Tension Bus`).
    #[serde(default)]
    pub label: Option<String>,
}

impl HamConfig {
    /// Checks whether a configuration file is empty (0 bytes or only comments/whitespace).
    pub fn is_empty_file(path: &Path) -> bool {
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() == 0 {
                return true;
            }
            if let Ok(content) = std::fs::read_to_string(path) {
                return content.lines().all(|line| {
                    let trimmed = line.trim();
                    trimmed.is_empty() || trimmed.starts_with('#')
                });
            }
        }
        false
    }

    /// Checks if a configuration file exists at explicit path or in standard locations.
    pub fn find_config(path: Option<&Path>) -> Option<PathBuf> {
        if let Some(p) = path {
            if p.exists() && !Self::is_empty_file(p) {
                Some(p.to_path_buf())
            } else {
                None
            }
        } else {
            Self::find_default_config()
        }
    }

    /// Loads configuration from an explicit file path or searches default standard locations.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let candidate_path = if let Some(p) = path {
            if !p.exists() {
                anyhow::bail!("Configuration file not found: {}", p.display());
            }
            Some(p.to_path_buf())
        } else {
            Self::find_default_config()
        };

        if let Some(config_file) = candidate_path {
            if Self::is_empty_file(&config_file) {
                anyhow::bail!("Configuration file is empty: {}", config_file.display());
            }
            tracing::info!("Loading configuration from {}", config_file.display());
            let s = config::Config::builder()
                .add_source(config::File::from(config_file.clone()))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to read configuration: {e}"))?;
            let mut cfg = s
                .try_deserialize::<HamConfig>()
                .map_err(|e| anyhow::anyhow!("Failed to parse configuration: {e}"))?;
            cfg.config_path = Some(config_file);
            cfg.normalize();
            Ok(cfg)
        } else {
            tracing::info!("No configuration file found; using default hamradio configuration");
            let mut cfg = Self::default();
            cfg.normalize();
            Ok(cfg)
        }
    }

    /// Normalizes configuration defaults, such as deriving node_id from callsign
    /// and propagating root callsign to CLAs.
    pub fn normalize(&mut self) {
        if let Some(ref mut d) = self.storage.data_dir {
            *d = expand_tilde(d);
        }
        if let Some(ref mut p) = self.storage.sqlite_path {
            *p = expand_tilde(p);
        }
        if let Some(ref cs) = self.callsign {
            if self.node_id == default_node_id() {
                self.node_id = format!("dtn://{}/", cs.to_lowercase());
            }
            // Propagate callsign to CLAs that require it if missing
            for cla in &mut self.clas {
                if let cla::ClaType::MercuryArq(ref mut m_cfg) = cla.cla_type
                    && m_cfg.my_callsign.is_none()
                {
                    m_cfg.my_callsign = Some(cs.clone());
                }
            }
        }
    }

    fn find_default_config() -> Option<PathBuf> {
        let local_names = ["dtnpm.toml", "dtnpm.yaml", "config.toml", "config.yaml"];
        for name in local_names {
            let p = PathBuf::from(name);
            if p.exists() && !Self::is_empty_file(&p) {
                return Some(p);
            }
        }

        if let Some(base_dirs) = directories::BaseDirs::new() {
            let user_dir = base_dirs.config_dir().join("dtnpm");
            for name in ["config.toml", "config.yaml"] {
                let user_conf = user_dir.join(name);
                if user_conf.exists() && !Self::is_empty_file(&user_conf) {
                    return Some(user_conf);
                }
            }
        }

        for sys_path in ["/etc/dtnpm/config.toml", "/etc/dtnpm/config.yaml"] {
            let sys_conf = PathBuf::from(sys_path);
            if sys_conf.exists() && !Self::is_empty_file(&sys_conf) {
                return Some(sys_conf);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_byte_size() {
        assert_eq!(parse_byte_size("1024").unwrap(), 1024);
        assert_eq!(parse_byte_size("1024B").unwrap(), 1024);
        assert_eq!(parse_byte_size("1KB").unwrap(), 1024);
        assert_eq!(parse_byte_size("1KiB").unwrap(), 1024);
        assert_eq!(parse_byte_size("300MB").unwrap(), 300 * 1024 * 1024);
        assert_eq!(parse_byte_size("300MiB").unwrap(), 300 * 1024 * 1024);
        assert_eq!(
            parse_byte_size("1.5GB").unwrap(),
            (1.5 * 1024.0 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(parse_byte_size(" 500 MB ").unwrap(), 500 * 1024 * 1024);
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("invalid").is_err());
        assert!(parse_byte_size("100XYZ").is_err());
    }

    #[test]
    fn test_serde_application_quota_config() {
        // 1. With human-readable string "500MB"
        let yaml_str = r#"
application:
  quota:
    max-storage: "500MB"
"#;
        let cfg: HamConfig = yaml_serde::from_str(yaml_str).unwrap();
        assert_eq!(cfg.application.quota.max_storage, 500 * 1024 * 1024);

        // 2. With numeric value
        let yaml_num = r#"
application:
  quota:
    max-storage: 10485760
"#;
        let cfg_num: HamConfig = yaml_serde::from_str(yaml_num).unwrap();
        assert_eq!(cfg_num.application.quota.max_storage, 10485760);

        // 3. Omitted (default 300MB)
        let yaml_default = "node-id: 'dtn://test/'";
        let cfg_default: HamConfig = yaml_serde::from_str(yaml_default).unwrap();
        assert_eq!(
            cfg_default.application.quota.max_storage,
            DEFAULT_APP_MAX_STORAGE_BYTES
        );
    }

    #[test]
    fn test_cla_type_other_yaml_toml_and_config_crate() {
        let yaml = r#"
node-id: "dtn://f4klo/"
clas:
  - name: "ltp-radio"
    type: ltp
    engine-id: 42
    max-mtu: 220
  - name: "hqfbp-kiss"
    type: hqfbp
    bitrate: 1200
  - name: "tcp-main"
    type: tcpclv4
    require-tls: false
  - name: "vara-hf"
    type: mercury-arq
    my-callsign: "F4KLO"
"#;
        let cfg_yaml: HamConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(cfg_yaml.clas.len(), 4);
        assert_eq!(cfg_yaml.clas[0].cla_type.type_name(), "ltp");
        assert_eq!(cfg_yaml.clas[1].cla_type.type_name(), "hqfbp");
        assert_eq!(cfg_yaml.clas[2].cla_type.type_name(), "tcpclv4");
        assert_eq!(cfg_yaml.clas[3].cla_type.type_name(), "mercury-arq");

        let config_parsed = config::Config::builder()
            .add_source(config::File::from_str(yaml, config::FileFormat::Yaml))
            .build()
            .unwrap()
            .try_deserialize::<HamConfig>()
            .unwrap();
        assert_eq!(config_parsed.clas.len(), 4);
        assert_eq!(config_parsed.clas[0].cla_type.type_name(), "ltp");
        assert_eq!(config_parsed.clas[1].cla_type.type_name(), "hqfbp");

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct DummyLtp {
            engine_id: u64,
            max_mtu: u64,
        }
        let parsed_ltp: DummyLtp = config_parsed.clas[0]
            .cla_type
            .parse_as("ltp")
            .unwrap()
            .unwrap();
        assert_eq!(parsed_ltp.engine_id, 42);
        assert_eq!(parsed_ltp.max_mtu, 220);

        let toml_str = r#"
node-id = "dtn://f4klo/"

[[clas]]
name = "hqfbp-toml"
type = "hqfbp"
bitrate = 2400
"#;
        let cfg_toml = config::Config::builder()
            .add_source(config::File::from_str(toml_str, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize::<HamConfig>()
            .unwrap();
        assert_eq!(cfg_toml.clas[0].cla_type.type_name(), "hqfbp");
    }

    #[test]
    fn test_expand_and_contract_tilde() {
        let p = Path::new("~/sub/dir");
        let expanded = expand_tilde(p);
        assert!(!expanded.to_string_lossy().starts_with("~/"));
        if let Some(base) = directories::BaseDirs::new() {
            let abs = base.home_dir().join("test.yaml");
            assert_eq!(contract_tilde(&abs), "~/test.yaml");
        }
    }

    #[test]
    fn test_iam_and_tls_toml_config_parsing() {
        let toml_str = r#"
callsign = "F4KLO"

[auth]
mode = "proxy"
admin_users = ["f4klo"]
admin_groups = ["dtn_admins", "admins"]
policy_path = "/etc/dtnpm/policy.rego"
session_ttl = "12h"

[auth.proxy]
header_user = "Remote-User"
header_groups = "Remote-Groups"
trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"]

[grpc]
enabled = true
address = "127.0.0.1:50051"

[grpc.auth]
enabled = true
socket_path = "/run/dtnpm/dtnpm.sock"
socket_group = "dtnpm"
socket_mode = "0660"

[[grpc.auth.tokens]]
name = "ltp-kiss-daemon"
token = "tok-123"
role = "Admin"

[tls]
enabled = true
cert_path = "/etc/dtnpm/cert.pem"
key_path = "/etc/dtnpm/key.pem"
"#;

        let cfg = config::Config::builder()
            .add_source(config::File::from_str(toml_str, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize::<HamConfig>()
            .unwrap();

        assert_eq!(cfg.auth.mode, AuthMode::Proxy);
        assert_eq!(cfg.auth.admin_users, vec!["f4klo"]);
        assert_eq!(cfg.auth.admin_groups, vec!["dtn_admins", "admins"]);
        assert_eq!(
            cfg.auth.policy_path.as_deref(),
            Some(Path::new("/etc/dtnpm/policy.rego"))
        );
        assert_eq!(parse_duration_secs(&cfg.auth.session_ttl), 12 * 3600);
        assert_eq!(cfg.auth.proxy.header_user, "Remote-User");
        assert_eq!(
            cfg.auth.proxy.trusted_proxies,
            vec!["127.0.0.1/32", "10.0.0.0/8"]
        );
        assert!(cfg.grpc.auth.enabled);
        assert_eq!(
            cfg.grpc.auth.socket_path.as_deref(),
            Some(Path::new("/run/dtnpm/dtnpm.sock"))
        );
        assert_eq!(cfg.grpc.auth.tokens.len(), 1);
        assert_eq!(cfg.grpc.auth.tokens[0].role, "Admin");
        assert!(cfg.tls.enabled);
    }

    #[test]
    fn test_cla_aliases_and_rego_routing_config_parsing() {
        let yaml = r#"
node-id: "dtn://f4jxq/"
rego-routing:
  policy-dir: "/etc/dtnpm/policies"
  record-treb: true
  supported-aliases: ["QO100"]
  trapped-aliases: ["WIDE3"]
  ansrvr:
    enabled: true
    default-ttl-secs: 3600
    max-groups: 64
clas:
  - name: "vhf-kiss"
    type: hqfbp
    aliases: ["vhf", "2m", "VHF"]
  - name: "tcp-main"
    type: tcpclv4
"#;
        let cfg: HamConfig = yaml_serde::from_str(yaml).unwrap();
        let rego = cfg.rego_routing.as_ref().unwrap();
        assert_eq!(rego.record_treb, Some(true));
        assert_eq!(rego.supported_aliases, vec!["QO100"]);
        assert_eq!(rego.trapped_aliases, vec!["WIDE3"]);
        assert!(rego.ansrvr.enabled);
        assert_eq!(rego.ansrvr.service_name, "ansrvr");
        assert_eq!(rego.ansrvr.default_ttl_secs, 3600);
        assert_eq!(rego.ansrvr.max_groups, 64);
        assert_eq!(cfg.clas[0].effective_aliases(), vec!["2M", "HQFBP", "VHF"]);
        assert_eq!(cfg.clas[1].effective_aliases(), vec!["TCPCL"]);
    }

    #[test]
    fn test_multiple_file_clas_config_and_aliases() {
        let yaml = r#"
node-id: "dtn://f4jxq/"
clas:
  - name: "usb-club"
    type: file-cla
    aliases: ["usb"]
    outbox: "/tmp/usb/outbox"
    peers:
      "dtn://f4usb/": "/tmp/usb/inbox"
  - name: "ext-bridge"
    type: file
    aliases: ["ext"]
    outbox: "/tmp/ext/outbox"
    peers:
      "dtn://f4ext/": "/tmp/ext/inbox"
"#;
        let cfg_yaml: HamConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(cfg_yaml.clas.len(), 2);
        assert_eq!(cfg_yaml.clas[0].cla_type.type_name(), "file-cla");
        assert_eq!(cfg_yaml.clas[1].cla_type.type_name(), "file");
        assert_eq!(cfg_yaml.clas[0].effective_aliases(), vec!["FILE", "USB"]);
        assert_eq!(cfg_yaml.clas[1].effective_aliases(), vec!["EXT", "FILE"]);

        let toml_str = r#"
node-id = "dtn://f4jxq/"

[[clas]]
name = "usb-club"
type = "file-cla"
aliases = ["usb"]
outbox = "/tmp/usb/outbox"

[clas.peers]
"dtn://f4usb/" = "/tmp/usb/inbox"

[[clas]]
name = "ext-bridge"
type = "file"
aliases = ["ext"]
outbox = "/tmp/ext/outbox"

[clas.peers]
"dtn://f4ext/" = "/tmp/ext/inbox"
"#;
        let cfg_toml: HamConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg_toml.clas.len(), 2);
        assert_eq!(cfg_toml.clas[0].effective_aliases(), vec!["FILE", "USB"]);
        assert_eq!(cfg_toml.clas[1].effective_aliases(), vec!["EXT", "FILE"]);

        for cla_type in ["tcpclv4", "ltp", "hqfbp", "mercury-arq", "file-cla"] {
            let alias = cla::auto_cla_transport_alias(cla_type).unwrap();
            assert!(
                cla::BUILTIN_CLA_TRANSPORT_ALIASES.contains(&alias),
                "alias '{alias}' for '{cla_type}' missing from BUILTIN_CLA_TRANSPORT_ALIASES"
            );
        }
    }

    #[test]
    fn test_cla_type_case_insensitive_deserialization_and_parse_as() {
        let yaml = r#"
node-id: "dtn://f4case/"
clas:
  - name: "tcp-upper"
    type: TCPCLV4
    require-tls: false
  - name: "mercury-upper"
    type: MERCURY-ARQ
    my-callsign: "F4CASE"
  - name: "ltp-upper"
    type: LTP
    engine-id: 7
  - name: "file-upper"
    type: FILE-CLA
    outbox: "/tmp/upper/outbox"
"#;
        let cfg: HamConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(cfg.clas.len(), 4);
        assert!(matches!(cfg.clas[0].cla_type, cla::ClaType::TcpClv4(_)));
        assert!(matches!(cfg.clas[1].cla_type, cla::ClaType::MercuryArq(_)));
        assert_eq!(cfg.clas[0].effective_aliases(), vec!["TCPCL"]);
        assert_eq!(cfg.clas[1].effective_aliases(), vec!["MERCURY"]);
        assert_eq!(cfg.clas[2].effective_aliases(), vec!["LTP"]);
        assert_eq!(cfg.clas[3].effective_aliases(), vec!["FILE"]);

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct DummyLtp {
            engine_id: u64,
        }
        let parsed: DummyLtp = cfg.clas[2].cla_type.parse_as("ltp").unwrap().unwrap();
        assert_eq!(parsed.engine_id, 7);
    }
}
