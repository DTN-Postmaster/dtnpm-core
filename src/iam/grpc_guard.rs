//! Authenticated gRPC and Unix Domain Socket (UDS) gateway & client bridge.
//!
//! Enforces Bearer token authentication, Rego PBAC authorization, and Unix Domain Socket
//! transport in front of [`hardy_proto::server::GrpcServer`] without requiring changes to upstream `hardy-proto`.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hardy_async::{CancellationToken, async_trait};
use hardy_bpa::bpa::BpaRegistration;
use hardy_bpa::cla::{self, Cla, ClaInit};
use hardy_bpa::policy::FlowControllerFactory;
use hardy_bpa::routing::{self, RoutingAgent};
use hardy_bpa::services::{self, Application, Service};
use http::{HeaderValue, Request, Response, StatusCode, header};
use http_body_util::{Either, Empty};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::config::{GrpcAuthConfig, GrpcTokenEntry};
use crate::iam::policy::{ContextInput, PolicyEngine, RegoInput, RequestInput, UserInput};
use crate::internal_storage::InternalStorage;

type GuardBody = Either<Incoming, Empty<Bytes>>;

const GATE_TICKET_TTL: Duration = Duration::from_secs(10);
const MAX_GATE_TICKETS: usize = 256;

/// Classification of BPA registration operations authorized by [`GrpcSecurityGateway`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcRegistrationKind {
    Cla,
    Service,
    Application,
    Routing,
}

impl GrpcRegistrationKind {
    #[must_use]
    fn from_grpc_path(path: &str) -> Option<Self> {
        match path {
            "/cla.Cla/Register" => Some(Self::Cla),
            "/service.Service/Register" => Some(Self::Service),
            "/service.Application/Register" => Some(Self::Application),
            "/routing.RoutingAgent/Register" => Some(Self::Routing),
            _ => None,
        }
    }
}

struct GateTicket {
    id: u64,
    kind: GrpcRegistrationKind,
    expires_at: Instant,
}

/// Short-lived authorization gate bridging [`GrpcSecurityGateway`] and the internal
/// loopback [`hardy_proto::server::GrpcServer`].
///
/// Prevents local unprivileged processes from bypassing gateway authentication and PBAC
/// by connecting directly to the internal ephemeral loopback socket.
#[derive(Default)]
pub struct GrpcRegistrationGate {
    next_id: AtomicU64,
    tickets: Mutex<VecDeque<GateTicket>>,
}

impl GrpcRegistrationGate {
    /// Creates an empty registration authorization gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn grant_ticket(&self, kind: GrpcRegistrationKind) -> Option<u64> {
        let now = Instant::now();
        let mut queue = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(front) = queue.front() {
            if front.expires_at <= now {
                queue.pop_front();
            } else {
                break;
            }
        }
        if queue.len() >= MAX_GATE_TICKETS {
            queue.pop_front();
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        queue.push_back(GateTicket {
            id,
            kind,
            expires_at: now + GATE_TICKET_TTL,
        });
        Some(id)
    }

    fn revoke_ticket(&self, id: u64) {
        let mut queue = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = queue.iter().position(|t| t.id == id) {
            queue.remove(pos);
        }
    }

    fn consume_ticket(&self, kind: GrpcRegistrationKind) -> bool {
        let now = Instant::now();
        let mut queue = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        queue.retain(|t| t.expires_at > now);
        if let Some(pos) = queue.iter().position(|t| t.kind == kind) {
            queue.remove(pos);
            true
        } else {
            false
        }
    }
}

/// Wraps a [`BpaRegistration`] target and rejects registrations that were not authorized
/// through [`GrpcSecurityGateway`].
pub struct GuardedBpaRegistration {
    inner: Arc<dyn BpaRegistration>,
    gate: Arc<GrpcRegistrationGate>,
}

impl GuardedBpaRegistration {
    /// Wraps `inner` with an authorization check against `gate`.
    #[must_use]
    pub fn new(inner: Arc<dyn BpaRegistration>, gate: Arc<GrpcRegistrationGate>) -> Self {
        Self { inner, gate }
    }

    fn denied_box_err(op: &str) -> Box<dyn std::error::Error + Send + Sync> {
        warn!(
            operation = op,
            "Rejected direct unauthenticated registration bypassing GrpcSecurityGateway"
        );
        Box::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Direct unauthenticated gRPC registration '{op}' bypassing gateway denied"),
        ))
    }
}

#[async_trait]
impl BpaRegistration for GuardedBpaRegistration {
    async fn register_cla(
        &self,
        name: String,
        cla: Arc<dyn Cla>,
        policy: Option<Arc<dyn FlowControllerFactory>>,
        init: ClaInit,
    ) -> cla::Result<Vec<hardy_bpv7::eid::NodeId>> {
        if !self.gate.consume_ticket(GrpcRegistrationKind::Cla) {
            return Err(cla::Error::Internal(Self::denied_box_err("register_cla")));
        }
        self.inner.register_cla(name, cla, policy, init).await
    }

    async fn register_service(
        &self,
        service_id: hardy_bpv7::eid::Service,
        service: Arc<dyn Service>,
    ) -> services::Result<hardy_bpv7::eid::Eid> {
        if !self.gate.consume_ticket(GrpcRegistrationKind::Service) {
            return Err(services::Error::Internal(Self::denied_box_err(
                "register_service",
            )));
        }
        self.inner.register_service(service_id, service).await
    }

    async fn register_application(
        &self,
        service_id: hardy_bpv7::eid::Service,
        application: Arc<dyn Application>,
    ) -> services::Result<hardy_bpv7::eid::Eid> {
        if !self.gate.consume_ticket(GrpcRegistrationKind::Application) {
            return Err(services::Error::Internal(Self::denied_box_err(
                "register_application",
            )));
        }
        self.inner
            .register_application(service_id, application)
            .await
    }

    async fn register_dynamic_service(
        &self,
        service: Arc<dyn Service>,
    ) -> services::Result<hardy_bpv7::eid::Eid> {
        if !self.gate.consume_ticket(GrpcRegistrationKind::Service) {
            return Err(services::Error::Internal(Self::denied_box_err(
                "register_dynamic_service",
            )));
        }
        self.inner.register_dynamic_service(service).await
    }

    async fn register_dynamic_application(
        &self,
        application: Arc<dyn Application>,
    ) -> services::Result<hardy_bpv7::eid::Eid> {
        if !self.gate.consume_ticket(GrpcRegistrationKind::Application) {
            return Err(services::Error::Internal(Self::denied_box_err(
                "register_dynamic_application",
            )));
        }
        self.inner.register_dynamic_application(application).await
    }

    async fn register_routing_agent(
        &self,
        name: String,
        agent: Arc<dyn RoutingAgent>,
    ) -> routing::Result<Vec<hardy_bpv7::eid::NodeId>> {
        if !self.gate.consume_ticket(GrpcRegistrationKind::Routing) {
            return Err(routing::Error::Internal(Self::denied_box_err(
                "register_routing_agent",
            )));
        }
        self.inner.register_routing_agent(name, agent).await
    }
}

/// Maps a gRPC HTTP/2 URI path (e.g. `"/cla.Cla/Register"`) to a Rego action identifier.
#[must_use]
pub fn map_grpc_path_to_action(path: &str) -> String {
    match path {
        "/cla.Cla/Register" => "grpc:cla:register".to_string(),
        "/service.Service/Register" => "grpc:service:register".to_string(),
        "/service.Application/Register" => "grpc:application:register".to_string(),
        "/routing.RoutingAgent/Register" => "grpc:routing:register".to_string(),
        other => format!("grpc:{other}"),
    }
}

fn empty_grpc_error(grpc_status: &'static str, message: &'static str) -> Response<GuardBody> {
    let mut resp = Response::new(Either::Right(Empty::new()));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("grpc-status"),
        HeaderValue::from_static(grpc_status),
    );
    resp.headers_mut().insert(
        header::HeaderName::from_static("grpc-message"),
        HeaderValue::from_static(message),
    );
    resp
}

fn extract_bearer_token(req: &Request<Incoming>) -> Option<String> {
    let header_val = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let trimmed = header_val.trim();
    if let Some(rest) = trimmed.strip_prefix("Bearer ") {
        let tok = rest.trim();
        if !tok.is_empty() {
            return Some(tok.to_string());
        }
    } else if let Some(rest) = trimmed.strip_prefix("bearer ") {
        let tok = rest.trim();
        if !tok.is_empty() {
            return Some(tok.to_string());
        }
    }
    None
}

fn verify_static_token<'a>(
    tokens: &'a [GrpcTokenEntry],
    candidate: &str,
) -> Option<&'a GrpcTokenEntry> {
    let cand_bytes = candidate.as_bytes();
    let mut matched: Option<&'a GrpcTokenEntry> = None;
    for entry in tokens {
        let entry_bytes = entry.token.as_bytes();
        let is_eq =
            entry_bytes.len() == cand_bytes.len() && bool::from(entry_bytes.ct_eq(cand_bytes));
        if is_eq {
            matched = Some(entry);
        }
    }
    matched
}

fn resolve_grpc_user(
    req: &Request<Incoming>,
    is_uds: bool,
    static_tokens: &[GrpcTokenEntry],
    internal_storage: Option<&InternalStorage>,
) -> UserInput {
    if let Some(raw_token) = extract_bearer_token(req) {
        if let Some(entry) = verify_static_token(static_tokens, &raw_token) {
            let role = InternalStorage::normalize_iam_role(&entry.role)
                .unwrap_or("Operator")
                .to_string();
            return UserInput {
                authenticated: true,
                username: entry.name.clone(),
                roles: vec![role],
                auth_method: if is_uds {
                    "uds+token".to_string()
                } else {
                    "token".to_string()
                },
            };
        }

        if let Some(storage) = internal_storage
            && let Ok(Some(record)) = storage.verify_iam_api_token(&raw_token)
        {
            return UserInput {
                authenticated: true,
                username: record.name,
                roles: vec![record.role],
                auth_method: if is_uds {
                    "uds+token".to_string()
                } else {
                    "token".to_string()
                },
            };
        }
    }

    if is_uds {
        return UserInput {
            authenticated: true,
            username: "local-uds".to_string(),
            roles: vec!["Admin".to_string()],
            auth_method: "uds".to_string(),
        };
    }

    UserInput::default()
}

fn parse_octal_mode(mode_str: &str) -> u32 {
    let trimmed = mode_str
        .trim()
        .trim_start_matches("0o")
        .trim_start_matches('0');
    if trimmed.is_empty() {
        return 0o660;
    }
    u32::from_str_radix(trimmed, 8).unwrap_or(0o660)
}

#[cfg(unix)]
fn apply_unix_socket_permissions(path: &Path, auth_cfg: &GrpcAuthConfig) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = parse_octal_mode(&auth_cfg.socket_mode);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;

    if let Some(ref group_name) = auth_cfg.socket_group
        && let Ok(groups_content) = std::fs::read_to_string("/etc/group")
    {
        for line in groups_content.lines() {
            let mut parts = line.split(':');
            let Some(name) = parts.next() else { continue };
            let _pw = parts.next();
            let Some(gid_str) = parts.next() else {
                continue;
            };
            if name == group_name
                && let Ok(gid) = gid_str.parse::<u32>()
                && let Err(e) = std::os::unix::fs::chown(path, None, Some(gid))
            {
                warn!(
                    socket = %path.display(),
                    group = %group_name,
                    "Failed to chgrp Unix socket: {e}"
                );
            }
        }
    }
    Ok(())
}

/// Server-side HTTP/2 authentication & PBAC gateway for [`hardy_proto::server::GrpcServer`].
pub struct GrpcSecurityGateway;

impl GrpcSecurityGateway {
    /// Spawns the configured gRPC TCP auth proxy and/or Unix Domain Socket listener
    /// forwarding authorized requests to `internal_grpc_addr`.
    pub async fn start(
        public_tcp_addr: SocketAddr,
        internal_grpc_addr: SocketAddr,
        auth_cfg: GrpcAuthConfig,
        station_callsign: Option<String>,
        policy_engine: Arc<PolicyEngine>,
        internal_storage: Option<InternalStorage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Option<PathBuf>> {
        Self::start_with_gate(
            public_tcp_addr,
            internal_grpc_addr,
            auth_cfg,
            station_callsign,
            policy_engine,
            internal_storage,
            None,
            cancel,
        )
        .await
    }

    /// Spawns the configured gRPC TCP auth proxy and/or Unix Domain Socket listener
    /// with an optional [`GrpcRegistrationGate`] guarding the internal loopback server.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_gate(
        public_tcp_addr: SocketAddr,
        internal_grpc_addr: SocketAddr,
        auth_cfg: GrpcAuthConfig,
        station_callsign: Option<String>,
        policy_engine: Arc<PolicyEngine>,
        internal_storage: Option<InternalStorage>,
        registration_gate: Option<Arc<GrpcRegistrationGate>>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Option<PathBuf>> {
        let mut active_socket_path: Option<PathBuf> = None;

        if auth_cfg.enabled {
            let tcp_listener = TcpListener::bind(public_tcp_addr).await?;
            info!(
                "gRPC authenticated TCP gateway listening on {} -> {}",
                public_tcp_addr, internal_grpc_addr
            );

            let cfg_clone = auth_cfg.clone();
            let callsign_clone = station_callsign.clone();
            let policy_clone = policy_engine.clone();
            let storage_clone = internal_storage.clone();
            let gate_clone = registration_gate.clone();
            let cancel_clone = cancel.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => break,
                        accept_res = tcp_listener.accept() => {
                            match accept_res {
                                Ok((stream, peer_addr)) => {
                                    let _ = stream.set_nodelay(true);
                                    let cfg = cfg_clone.clone();
                                    let callsign = callsign_clone.clone();
                                    let policy = policy_clone.clone();
                                    let storage = storage_clone.clone();
                                    let gate = gate_clone.clone();
                                    let peer_ip = peer_addr.ip().to_string();

                                    tokio::spawn(async move {
                                        if let Err(e) = handle_h2_gateway_conn(
                                            TokioIo::new(stream),
                                            internal_grpc_addr,
                                            peer_ip,
                                            false,
                                            cfg,
                                            callsign,
                                            policy,
                                            storage,
                                            gate,
                                        ).await {
                                            debug!("gRPC TCP gateway connection closed: {e}");
                                        }
                                    });
                                }
                                Err(e) => {
                                    warn!("gRPC TCP gateway accept error: {e}");
                                }
                            }
                        }
                    }
                }
            });
        }

        if let Some(ref sock_path) = auth_cfg.socket_path {
            if let Some(parent) = sock_path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            if sock_path.exists() {
                let _ = std::fs::remove_file(sock_path);
            }
            let uds_listener = UnixListener::bind(sock_path)?;
            #[cfg(unix)]
            apply_unix_socket_permissions(sock_path, &auth_cfg)?;
            info!(
                "gRPC Unix Domain Socket listener bound at {} -> {}",
                sock_path.display(),
                internal_grpc_addr
            );
            active_socket_path = Some(sock_path.clone());

            let cfg_clone = auth_cfg.clone();
            let callsign_clone = station_callsign;
            let policy_clone = policy_engine;
            let storage_clone = internal_storage;
            let gate_clone = registration_gate;
            let cancel_clone = cancel;
            let sock_cleanup = sock_path.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => {
                            let _ = std::fs::remove_file(&sock_cleanup);
                            break;
                        }
                        accept_res = uds_listener.accept() => {
                            match accept_res {
                                Ok((stream, _addr)) => {
                                    let cfg = cfg_clone.clone();
                                    let callsign = callsign_clone.clone();
                                    let policy = policy_clone.clone();
                                    let storage = storage_clone.clone();
                                    let gate = gate_clone.clone();

                                    tokio::spawn(async move {
                                        if let Err(e) = handle_h2_gateway_conn(
                                            TokioIo::new(stream),
                                            internal_grpc_addr,
                                            "unix-socket".to_string(),
                                            true,
                                            cfg,
                                            callsign,
                                            policy,
                                            storage,
                                            gate,
                                        ).await {
                                            debug!("gRPC UDS gateway connection closed: {e}");
                                        }
                                    });
                                }
                                Err(e) => {
                                    warn!("gRPC UDS accept error: {e}");
                                }
                            }
                        }
                    }
                }
            });
        }

        Ok(active_socket_path)
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_h2_gateway_conn<IO>(
    client_io: TokioIo<IO>,
    upstream_addr: SocketAddr,
    client_ip: String,
    is_uds: bool,
    auth_cfg: GrpcAuthConfig,
    station_callsign: Option<String>,
    policy_engine: Arc<PolicyEngine>,
    internal_storage: Option<InternalStorage>,
    registration_gate: Option<Arc<GrpcRegistrationGate>>,
) -> anyhow::Result<()>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let upstream_stream = TcpStream::connect(upstream_addr).await?;
    let _ = upstream_stream.set_nodelay(true);
    let (upstream_sender, upstream_conn) =
        hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Incoming>(TokioIo::new(upstream_stream))
            .await?;

    tokio::spawn(async move {
        if let Err(e) = upstream_conn.await {
            debug!("gRPC gateway upstream connection ended: {e}");
        }
    });

    let sender_cell = Arc::new(tokio::sync::Mutex::new(upstream_sender));

    let svc = service_fn(move |req: Request<Incoming>| {
        let sender_cell = sender_cell.clone();
        let auth_cfg = auth_cfg.clone();
        let callsign = station_callsign.clone();
        let policy = policy_engine.clone();
        let storage = internal_storage.clone();
        let gate = registration_gate.clone();
        let client_ip = client_ip.clone();

        async move {
            let path = req.uri().path().to_string();
            let action = map_grpc_path_to_action(&path);
            let reg_kind = GrpcRegistrationKind::from_grpc_path(&path);
            let user = resolve_grpc_user(&req, is_uds, &auth_cfg.tokens, storage.as_ref());

            let auth_mode = if is_uds {
                "uds".to_string()
            } else if auth_cfg.enabled {
                "local".to_string()
            } else {
                "none".to_string()
            };

            let rego_input = RegoInput {
                user: user.clone(),
                request: RequestInput {
                    interface: "grpc".to_string(),
                    method: "GRPC".to_string(),
                    path,
                    action,
                    client_ip,
                },
                context: ContextInput {
                    auth_mode,
                    station_callsign: callsign,
                },
            };

            if !policy.allow(&rego_input) {
                if !user.authenticated {
                    return Ok::<_, Infallible>(empty_grpc_error(
                        "16",
                        "Missing or invalid gRPC bearer token",
                    ));
                }
                return Ok::<_, Infallible>(empty_grpc_error(
                    "7",
                    "gRPC action denied by security policy",
                ));
            }

            let ticket_id = gate
                .as_ref()
                .zip(reg_kind)
                .and_then(|(g, kind)| g.grant_ticket(kind));

            let mut guard = sender_cell.lock().await;
            if let Err(e) = guard.ready().await {
                if let (Some(g), Some(id)) = (&gate, ticket_id) {
                    g.revoke_ticket(id);
                }
                warn!("gRPC upstream not ready: {e}");
                return Ok::<_, Infallible>(empty_grpc_error("14", "Upstream BPA unavailable"));
            }
            let fut = guard.send_request(req);
            drop(guard);

            match fut.await {
                Ok(resp) => Ok::<_, Infallible>(resp.map(Either::Left)),
                Err(e) => {
                    if let (Some(g), Some(id)) = (&gate, ticket_id) {
                        g.revoke_ticket(id);
                    }
                    warn!("gRPC upstream request failed: {e}");
                    Ok::<_, Infallible>(empty_grpc_error("14", "Upstream BPA request failed"))
                }
            }
        }
    });

    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(client_io, svc)
        .await
        .map_err(|e| anyhow::anyhow!("gRPC gateway HTTP/2 server error: {e}"))
}

/// Drop handle that stops the client-side gRPC Bearer/UDS local bridge when dropped.
pub struct GrpcBridgeGuard {
    cancel: CancellationToken,
}

impl Drop for GrpcBridgeGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn parse_tcp_host_port(endpoint: &str) -> String {
    let stripped = endpoint
        .trim()
        .strip_prefix("http://")
        .or_else(|| endpoint.trim().strip_prefix("https://"))
        .unwrap_or_else(|| endpoint.trim());
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

/// Resolves optional `token` / `socket_path` (falling back to `DTN_HDY_TOKEN` and `DTN_HDY_SOCKET`).
///
/// When either a Bearer token or a Unix Domain Socket path is provided, this spawns a local
/// ephemeral HTTP/2 bridge on `127.0.0.1:0` so [`hardy_proto::client::RemoteBpa`] can transmit
/// `Authorization: Bearer <token>` and/or connect over UDS transparently.
pub fn prepare_grpc_endpoint(
    raw_endpoint: &str,
    token: Option<&str>,
    socket_path: Option<&str>,
) -> anyhow::Result<(String, Option<GrpcBridgeGuard>)> {
    let resolved_token = token
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            std::env::var("DTN_HDY_TOKEN")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });

    let resolved_socket = socket_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("DTN_HDY_SOCKET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        });

    if resolved_token.is_none() && resolved_socket.is_none() {
        return Ok((raw_endpoint.to_string(), None));
    }

    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    std_listener.set_nonblocking(true)?;
    let local_addr = std_listener.local_addr()?;

    let handle = tokio::runtime::Handle::try_current().map_err(|_| {
        anyhow::anyhow!("prepare_grpc_endpoint with auth/socket requires an active Tokio runtime")
    })?;
    let listener = {
        let _guard = handle.enter();
        TcpListener::from_std(std_listener)?
    };

    let cancel = CancellationToken::new();
    let cancel_task = cancel.clone();
    let target_tcp = parse_tcp_host_port(raw_endpoint);

    handle.spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_task.cancelled() => break,
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _)) => {
                            let _ = stream.set_nodelay(true);
                            let token_clone = resolved_token.clone();
                            let sock_clone = resolved_socket.clone();
                            let tcp_clone = target_tcp.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_client_bridge_conn(
                                    TokioIo::new(stream),
                                    tcp_clone,
                                    sock_clone,
                                    token_clone,
                                ).await {
                                    debug!("gRPC client bridge connection ended: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!("gRPC client bridge accept error: {e}");
                        }
                    }
                }
            }
        }
    });

    Ok((
        format!("http://{local_addr}"),
        Some(GrpcBridgeGuard { cancel }),
    ))
}

async fn handle_client_bridge_conn(
    client_io: TokioIo<TcpStream>,
    target_tcp: String,
    target_socket: Option<PathBuf>,
    token: Option<String>,
) -> anyhow::Result<()> {
    let mut upstream_sender = if let Some(ref sock_path) = target_socket {
        let uds = UnixStream::connect(sock_path).await?;
        let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Incoming>(TokioIo::new(uds))
            .await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    } else {
        let tcp = TcpStream::connect(&target_tcp).await?;
        let _ = tcp.set_nodelay(true);
        let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Incoming>(TokioIo::new(tcp))
            .await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    };

    // Wait for first ready state before serving requests over this stream
    let _ = upstream_sender.ready().await;
    let sender_cell = Arc::new(tokio::sync::Mutex::new(upstream_sender));

    let svc = service_fn(move |mut req: Request<Incoming>| {
        let sender_cell = sender_cell.clone();
        let token = token.clone();
        async move {
            if let Some(ref tok) = token
                && let Ok(val) = HeaderValue::from_str(&format!("Bearer {tok}"))
            {
                req.headers_mut().insert(header::AUTHORIZATION, val);
            }
            let mut guard = sender_cell.lock().await;
            if let Err(e) = guard.ready().await {
                warn!("gRPC bridge upstream not ready: {e}");
                return Ok::<_, Infallible>(empty_grpc_error("14", "BPA unavailable"));
            }
            let fut = guard.send_request(req);
            drop(guard);
            match fut.await {
                Ok(resp) => Ok::<_, Infallible>(resp.map(Either::Left)),
                Err(e) => {
                    warn!("gRPC bridge forward failed: {e}");
                    Ok::<_, Infallible>(empty_grpc_error("14", "BPA bridge request failed"))
                }
            }
        }
    });

    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(client_io, svc)
        .await
        .map_err(|e| anyhow::anyhow!("gRPC client bridge server error: {e}"))
}

/// Convenience helper for standalone binaries using [`hardy_proto::client::RemoteBpa`].
pub fn create_remote_bpa(
    raw_endpoint: &str,
    token: Option<&str>,
    socket_path: Option<&str>,
) -> anyhow::Result<(hardy_proto::client::RemoteBpa, Option<GrpcBridgeGuard>)> {
    let (effective_endpoint, guard) = prepare_grpc_endpoint(raw_endpoint, token, socket_path)?;
    Ok((
        hardy_proto::client::RemoteBpa::new(effective_endpoint),
        guard,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hardy_bpa::bpa::BpaRegistration;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn test_grpc_security_gateway_token_and_pbac() {
        let internal_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mock_bpa = Arc::new(crate::mock_bpa::MockBpa::new("dtn://test-node/"));
        let gate = Arc::new(GrpcRegistrationGate::new());
        let guarded_bpa = Arc::new(GuardedBpaRegistration::new(mock_bpa.clone(), gate.clone()));
        let grpc_cfg = hardy_proto::server::Config {
            address: internal_addr,
            services: vec!["cla".to_string(), "service".to_string()],
        };
        let grpc_server = hardy_proto::server::GrpcServer::new(&grpc_cfg, guarded_bpa).unwrap();
        let bound_internal = grpc_server.local_addr();
        let cancel = CancellationToken::new();
        let cancel_srv = cancel.clone();
        let _server_handle = tokio::spawn(async move {
            let _ = grpc_server.serve(cancel_srv).await;
        });

        // Allocate ephemeral public port for gateway
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let public_addr = probe.local_addr().unwrap();
        drop(probe);

        let policy = Arc::new(PolicyEngine::load(None).unwrap());
        let auth_cfg = GrpcAuthConfig {
            enabled: true,
            socket_path: None,
            socket_group: None,
            socket_mode: "0660".to_string(),
            tokens: vec![
                GrpcTokenEntry {
                    name: "op-svc".to_string(),
                    token: "secret-operator-tok".to_string(),
                    role: "Operator".to_string(),
                },
                GrpcTokenEntry {
                    name: "adm-cla".to_string(),
                    token: "secret-admin-tok".to_string(),
                    role: "Admin".to_string(),
                },
            ],
        };

        GrpcSecurityGateway::start_with_gate(
            public_addr,
            bound_internal,
            auth_cfg,
            Some("TEST".to_string()),
            policy,
            None,
            Some(gate),
            cancel.clone(),
        )
        .await
        .unwrap();

        // 0. Direct loopback bypass against bound_internal -> REJECTED by GrpcRegistrationGate!
        let (bypass_bpa, _g0) =
            create_remote_bpa(&format!("http://{bound_internal}"), None, None).unwrap();
        let cla0 = Arc::new(crate::NoopSenderCla::default());
        let res0 = bypass_bpa
            .register_cla(
                "bypass-cla".to_string(),
                cla0,
                None,
                hardy_bpa::cla::ClaInit::default(),
            )
            .await;
        assert!(
            res0.is_err(),
            "Direct connection bypassing GrpcSecurityGateway MUST be rejected"
        );

        let public_url = format!("http://{public_addr}");

        // 1. Unauthenticated CLA registration -> rejected
        let (unauth_bpa, _g1) = create_remote_bpa(&public_url, None, None).unwrap();
        let cla1 = Arc::new(crate::NoopSenderCla::default());
        let res1 = unauth_bpa
            .register_cla(
                "unauth-cla".to_string(),
                cla1,
                None,
                hardy_bpa::cla::ClaInit::default(),
            )
            .await;
        assert!(res1.is_err(), "Unauthenticated gRPC call must be rejected");

        // 2. Operator token attempting CLA registration -> rejected (PERMISSION_DENIED)
        let (op_bpa, _g2) =
            create_remote_bpa(&public_url, Some("secret-operator-tok"), None).unwrap();
        let cla2 = Arc::new(crate::NoopSenderCla::default());
        let res2 = op_bpa
            .register_cla(
                "op-cla".to_string(),
                cla2,
                None,
                hardy_bpa::cla::ClaInit::default(),
            )
            .await;
        assert!(
            res2.is_err(),
            "Operator token must be denied for grpc:cla:register"
        );

        // 3. Operator token registering a Service -> ALLOWED!
        struct DummySvc(AtomicBool);
        #[hardy_async::async_trait]
        impl hardy_bpa::services::Service for DummySvc {
            async fn on_register(
                &self,
                _eid: &hardy_bpv7::eid::Eid,
                _sink: Box<dyn hardy_bpa::services::ServiceSink>,
            ) {
                self.0.store(true, Ordering::Relaxed);
            }
            async fn on_unregister(&self) {}
            async fn on_deliver(
                &self,
                _bundle_id: &hardy_bpv7::bundle::Id,
                _expiry: time::OffsetDateTime,
                _total_len: u64,
                _stream: &mut dyn hardy_bpa::stream::Receiver<hardy_bpa::cla::Segment>,
            ) -> hardy_bpa::services::Result<()> {
                Ok(())
            }
            async fn on_status_notify(
                &self,
                _bundle_id: &hardy_bpv7::bundle::Id,
                _from: &hardy_bpv7::eid::Eid,
                _kind: hardy_bpa::services::StatusNotify,
                _reason: hardy_bpv7::status_report::ReasonCode,
                _timestamp: Option<time::OffsetDateTime>,
            ) {
            }
        }
        let dummy_svc = Arc::new(DummySvc(AtomicBool::new(false)));
        let res3 = op_bpa
            .register_service(hardy_bpv7::eid::Service::Dtn("echo".into()), dummy_svc)
            .await;
        assert!(
            res3.is_ok(),
            "Operator token must be allowed for grpc:service:register, got: {:?}",
            res3
        );

        // 4. Admin token registering a CLA -> ALLOWED!
        let (adm_bpa, _g3) =
            create_remote_bpa(&public_url, Some("secret-admin-tok"), None).unwrap();
        let cla4 = Arc::new(crate::NoopSenderCla::default());
        let res4 = adm_bpa
            .register_cla(
                "adm-cla".to_string(),
                cla4,
                None,
                hardy_bpa::cla::ClaInit::default(),
            )
            .await;
        assert!(
            res4.is_ok(),
            "Admin token must be allowed for grpc:cla:register, got: {:?}",
            res4
        );

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_grpc_unix_domain_socket_transport() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("dtnpm.sock");

        let internal_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mock_bpa = Arc::new(crate::mock_bpa::MockBpa::new("dtn://uds-node/"));
        let grpc_cfg = hardy_proto::server::Config {
            address: internal_addr,
            services: vec!["cla".to_string()],
        };
        let grpc_server = hardy_proto::server::GrpcServer::new(&grpc_cfg, mock_bpa).unwrap();
        let bound_internal = grpc_server.local_addr();
        let cancel = CancellationToken::new();
        let cancel_srv = cancel.clone();
        let _server_handle = tokio::spawn(async move {
            let _ = grpc_server.serve(cancel_srv).await;
        });

        let policy = Arc::new(PolicyEngine::load(None).unwrap());
        let auth_cfg = GrpcAuthConfig {
            enabled: false,
            socket_path: Some(sock_path.clone()),
            socket_group: None,
            socket_mode: "0660".to_string(),
            tokens: Vec::new(),
        };

        GrpcSecurityGateway::start(
            "127.0.0.1:0".parse().unwrap(),
            bound_internal,
            auth_cfg,
            Some("UDS".to_string()),
            policy,
            None,
            cancel.clone(),
        )
        .await
        .unwrap();

        let (uds_bpa, _guard) = create_remote_bpa(
            "http://127.0.0.1:50051",
            None,
            Some(&sock_path.to_string_lossy()),
        )
        .unwrap();
        let cla = Arc::new(crate::NoopSenderCla::default());
        let res = uds_bpa
            .register_cla(
                "uds-cla".to_string(),
                cla,
                None,
                hardy_bpa::cla::ClaInit::default(),
            )
            .await;
        assert!(res.is_ok(), "UDS CLA registration must succeed: {:?}", res);

        cancel.cancel();
    }
}
