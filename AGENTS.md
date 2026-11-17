# Agent Guide — `dtnpm-core`

## 🎯 Mission
Provide the foundational and shared building blocks of the DTN Postmaster ecosystem: unified configuration (`HamConfig`), local SQLite persistence (`internal_storage`), convergence layer manager (`cla_manager`), service tracker (`service_tracker`), gRPC security gateway (`iam::grpc_guard`), PBAC access control, BPSec keystore (RFC 9172), and BPA client abstractions (`BpaClient`).

---

## 🛡️ Security Frameworks and Requirements

### 1. Cyber Resilience Act (CRA)
- **Secure-by-Default**:
  - No API or service may expose an unauthenticated interface by default.
  - The gRPC registration gate (`GrpcRegistrationGate` / `GuardedBpaRegistration`) prevents any bypass or TOCTOU race condition during BPA server startup.
- **Vulnerability Management & VEX**:
  - Dependencies audited via `cargo-audit` and `cargo-deny`.
  - The `.cargo/audit.toml` file records the VEX `not_affected` statement for `RUSTSEC-2026-0459` (SQLite `session` extension not compiled/unused).
  - YAML dependencies use `yaml_serde` (replacing `serde_yaml` and `unsafe-libyaml`).
  - GitHub Actions workflows use minimal `permissions: contents: read` and actions pinned by full 40-character SHA-1.
- **Security Policy**: Maintained in [SECURITY.md](SECURITY.md).

### 2. OWASP & Access Control
- **gRPC & UNIX Access Isolation**:
  - Mandatory authentication via Bearer token or dedicated local UNIX socket.
  - Tokens are resolved via `--token-file` / `DTN_HDY_TOKEN_FILE` without passing in plaintext in the process table.
- **PBAC (Policy-Based Access Control)**:
  - Authorization policies evaluated via the Rego engine (`regorus`), with strict handling of contexts and roles (`operator`, `admin`).
- **BPSec (RFC 9172)**:
  - Strict cryptographic verification by default: an unsigned bundle or one with a missing key must not be validated under `VerifyPolicy::Strict`.

---

## 🦀 Rust Engineering Standards

1. **Zero Panic / Zero Unwrap Rule**:
   - All code under `src/` must be 100% free of `.unwrap()`, `.expect()`, and `panic!`.
   - Use `?`, `thiserror`, and safe conversions.
   - Strict validation: `-D warnings -D clippy::unwrap_used -D clippy::panic`.
2. **Architecture Decision Records (ADRs)**:
   - Every architectural decision must be documented under `adr/` and indexed in [adr/README.md](adr/README.md).
3. **Documentation Language**:
   - English must be used as the language for all documentation, unless the file is suffixed with `.fr.md` or another language is explicitly requested in the prompt.

---

## ⚡ Critical Verification Commands

- `cargo fmt --all -- --check`
- `cargo clippy --offline --workspace --lib --bins -- -D warnings -D clippy::unwrap_used -D clippy::panic`
- `cargo test --offline --all-features`
- `./scripts/check-security.sh --strict`
- `./scripts/check-coverage.sh --summary-only`
