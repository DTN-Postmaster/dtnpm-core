//! Embedded OPA Rego Policy Engine for Policy-Based Access Control (PBAC).

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Compiled-in default Rego policy (`package dtn.ham.iam`).
pub const DEFAULT_POLICY_REGO: &str = include_str!("default_policy.rego");

const ALLOW_ENTRYPOINT: &str = "data.dtn.ham.iam.allow";

/// Identity section passed to the Rego evaluator as `input.user`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserInput {
    pub authenticated: bool,
    pub username: String,
    pub roles: Vec<String>,
    pub auth_method: String,
}

impl Default for UserInput {
    fn default() -> Self {
        Self {
            authenticated: false,
            username: String::new(),
            roles: Vec::new(),
            auth_method: "anonymous".to_string(),
        }
    }
}

/// Request section passed to the Rego evaluator as `input.request`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestInput {
    pub interface: String,
    pub method: String,
    pub path: String,
    pub action: String,
    pub client_ip: String,
}

/// Runtime station context passed to the Rego evaluator as `input.context`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextInput {
    pub auth_mode: String,
    pub station_callsign: Option<String>,
}

/// Complete Rego `input` document evaluated against `data.dtn.ham.iam.allow`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegoInput {
    pub user: UserInput,
    pub request: RequestInput,
    pub context: ContextInput,
}

/// Derived UI capability flags evaluated dynamically from the active Rego policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capabilities {
    pub can_manage_clas: bool,
    pub can_restart_server: bool,
    pub can_inject_bundles: bool,
}

/// Thread-safe compiled OPA Rego policy evaluator.
#[derive(Clone)]
pub struct PolicyEngine {
    compiled: regorus::CompiledPolicy,
}

impl PolicyEngine {
    /// Compiles the built-in Rego policy (`default_policy.rego`) or an external override file.
    pub fn load(custom_policy_path: Option<&Path>) -> anyhow::Result<Self> {
        let (source_name, rego_src) = match custom_policy_path {
            Some(path) => {
                let src = std::fs::read_to_string(path).with_context(|| {
                    format!(
                        "Failed to read external Rego policy file {}",
                        path.display()
                    )
                })?;
                (path.display().to_string(), src)
            }
            None => (
                "default_policy.rego".to_string(),
                DEFAULT_POLICY_REGO.to_string(),
            ),
        };

        Self::from_rego_str(&source_name, &rego_src)
    }

    /// Compiles a Rego policy directly from an in-memory source string.
    pub fn from_rego_str(source_name: &str, rego_src: &str) -> anyhow::Result<Self> {
        let mut engine = regorus::Engine::new();
        let is_rego_v1 = rego_src.contains("import rego.v1") || rego_src.contains("allow if ");
        engine.set_rego_v0(!is_rego_v1);
        engine
            .add_policy(source_name.to_string(), rego_src.to_string())
            .with_context(|| format!("Invalid Rego policy in {source_name}"))?;

        let entrypoint: Arc<str> = Arc::from(ALLOW_ENTRYPOINT);
        let compiled = engine
            .compile_with_entrypoint(&entrypoint)
            .with_context(|| format!("Failed to compile Rego entrypoint {ALLOW_ENTRYPOINT}"))?;

        Ok(Self { compiled })
    }

    /// Evaluates `data.dtn.ham.iam.allow` for the given [`RegoInput`].
    /// Any serialization or runtime evaluation error fails closed (`false`).
    #[must_use]
    pub fn allow(&self, input: &RegoInput) -> bool {
        let json_str = match serde_json::to_string(input) {
            Ok(s) => s,
            Err(e) => {
                warn!("PBAC input serialization failed (denying request): {e}");
                return false;
            }
        };

        let value = match regorus::Value::from_json_str(&json_str) {
            Ok(v) => v,
            Err(e) => {
                warn!("PBAC Rego value parse failed (denying request): {e}");
                return false;
            }
        };

        match self.compiled.eval_with_input(value) {
            Ok(res) => matches!(res.as_bool(), Ok(true)),
            Err(e) => {
                warn!("PBAC Rego policy evaluation error (denying request): {e}");
                false
            }
        }
    }

    /// Evaluates capability flags returned by `GET /api/v1/auth/me` so the frontend UI
    /// accurately reflects policy permissions without hardcoding role names.
    #[must_use]
    pub fn evaluate_capabilities(
        &self,
        user: &UserInput,
        context: &ContextInput,
        client_ip: &str,
    ) -> Capabilities {
        let eval_http = |method: &str, path: &str| {
            let input = RegoInput {
                user: user.clone(),
                request: RequestInput {
                    interface: "http".to_string(),
                    method: method.to_string(),
                    path: path.to_string(),
                    action: format!("http:{method}:{path}"),
                    client_ip: client_ip.to_string(),
                },
                context: context.clone(),
            };
            self.allow(&input)
        };

        Capabilities {
            can_manage_clas: eval_http("POST", "/api/v1/clas/connect"),
            can_restart_server: eval_http("POST", "/api/v1/system/restart"),
            can_inject_bundles: eval_http("POST", "/api/v1/bundles"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_input(
        auth_mode: &str,
        authenticated: bool,
        roles: &[&str],
        interface: &str,
        method: &str,
        path: &str,
        action: &str,
    ) -> RegoInput {
        RegoInput {
            user: UserInput {
                authenticated,
                username: if authenticated {
                    "f4abc".to_string()
                } else {
                    String::new()
                },
                roles: roles.iter().map(|s| s.to_string()).collect(),
                auth_method: if auth_mode == "none" {
                    "none".to_string()
                } else if authenticated {
                    "proxy".to_string()
                } else {
                    "anonymous".to_string()
                },
            },
            request: RequestInput {
                interface: interface.to_string(),
                method: method.to_string(),
                path: path.to_string(),
                action: action.to_string(),
                client_ip: "127.0.0.1".to_string(),
            },
            context: ContextInput {
                auth_mode: auth_mode.to_string(),
                station_callsign: Some("F4KLO".to_string()),
            },
        }
    }

    #[test]
    fn test_default_policy_none_mode_allows_everything() {
        let engine = PolicyEngine::load(None).unwrap();
        let req = mk_input(
            "none",
            false,
            &[],
            "http",
            "DELETE",
            "/api/v1/bundles",
            "http:DELETE:/api/v1/bundles",
        );
        assert!(engine.allow(&req));
    }

    #[test]
    fn test_default_policy_public_and_unauthenticated() {
        let engine = PolicyEngine::load(None).unwrap();
        // Public endpoints always allowed
        assert!(engine.allow(&mk_input(
            "local",
            false,
            &[],
            "http",
            "GET",
            "/api/v1/auth/me",
            "http:GET:/api/v1/auth/me"
        )));
        assert!(engine.allow(&mk_input(
            "local",
            false,
            &[],
            "http",
            "POST",
            "/api/v1/auth/login",
            "http:POST:/api/v1/auth/login"
        )));
        assert!(engine.allow(&mk_input(
            "local",
            false,
            &[],
            "http",
            "GET",
            "/index.html",
            "http:GET:/index.html"
        )));

        // Private API denied for anonymous in local mode
        assert!(!engine.allow(&mk_input(
            "local",
            false,
            &[],
            "http",
            "GET",
            "/api/v1/bundles",
            "http:GET:/api/v1/bundles"
        )));
    }

    #[test]
    fn test_default_policy_operator_vs_admin() {
        let engine = PolicyEngine::load(None).unwrap();

        // Operator GET allowed
        assert!(engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "GET",
            "/api/v1/config",
            "http:GET:/api/v1/config"
        )));

        // Operator operational POSTs allowed (bundles, chat, files read/sticky)
        assert!(engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "POST",
            "/api/v1/bundles",
            "http:POST:/api/v1/bundles"
        )));
        assert!(engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "POST",
            "/api/v1/bundles/inject",
            "http:POST:/api/v1/bundles/inject"
        )));
        assert!(engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "POST",
            "/api/chat/v1/messages",
            "http:POST:/api/chat/v1/messages"
        )));
        assert!(engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "POST",
            "/api/files/v1/abc123/sticky",
            "http:POST:/api/files/v1/abc123/sticky"
        )));

        // Operator admin mutations DENIED
        assert!(!engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "POST",
            "/api/v1/clas/connect",
            "http:POST:/api/v1/clas/connect"
        )));
        assert!(!engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "DELETE",
            "/api/v1/bundles",
            "http:DELETE:/api/v1/bundles"
        )));
        assert!(!engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "DELETE",
            "/api/files/v1/abc123",
            "http:DELETE:/api/files/v1/abc123"
        )));
        assert!(!engine.allow(&mk_input(
            "proxy",
            true,
            &["Operator"],
            "http",
            "POST",
            "/api/senml/v1/dashboard/cards",
            "http:POST:/api/senml/v1/dashboard/cards"
        )));

        // Admin allowed everywhere
        assert!(engine.allow(&mk_input(
            "proxy",
            true,
            &["Admin"],
            "http",
            "POST",
            "/api/v1/clas/connect",
            "http:POST:/api/v1/clas/connect"
        )));
        assert!(engine.allow(&mk_input(
            "proxy",
            true,
            &["Admin"],
            "http",
            "DELETE",
            "/api/v1/bundles",
            "http:DELETE:/api/v1/bundles"
        )));

        // gRPC Operator vs Admin
        assert!(engine.allow(&mk_input(
            "local",
            true,
            &["Operator"],
            "grpc",
            "GRPC",
            "/service.Service/Register",
            "grpc:service:register"
        )));
        assert!(!engine.allow(&mk_input(
            "local",
            true,
            &["Operator"],
            "grpc",
            "GRPC",
            "/cla.Cla/Register",
            "grpc:cla:register"
        )));
        assert!(engine.allow(&mk_input(
            "local",
            true,
            &["Admin"],
            "grpc",
            "GRPC",
            "/cla.Cla/Register",
            "grpc:cla:register"
        )));
    }

    #[test]
    fn test_custom_external_rego_policy_and_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.rego");
        std::fs::write(
            &path,
            r#"
package dtn.ham.iam
import rego.v1

default allow := false

allow if {
    input.user.authenticated == true
    input.user.username == "f4special"
}
"#,
        )
        .unwrap();

        let engine = PolicyEngine::load(Some(&path)).unwrap();
        let user = UserInput {
            authenticated: true,
            username: "f4special".to_string(),
            roles: vec!["Operator".to_string()],
            auth_method: "proxy".to_string(),
        };
        let ctx = ContextInput {
            auth_mode: "proxy".to_string(),
            station_callsign: None,
        };
        let caps = engine.evaluate_capabilities(&user, &ctx, "127.0.0.1");
        assert!(caps.can_manage_clas);
        assert!(caps.can_restart_server);
        assert!(caps.can_inject_bundles);

        let bad_path = dir.path().join("bad.rego");
        std::fs::write(&bad_path, "this is not valid rego syntax {{{").unwrap();
        assert!(PolicyEngine::load(Some(&bad_path)).is_err());
    }
}
