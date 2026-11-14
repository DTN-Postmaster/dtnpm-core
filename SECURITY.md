# Security Policy — `dtnpm-core`

## Supported Versions

| Version | Supported | Security Updates |
|---------|-----------|------------------|
| 0.2.x   | Yes       | Active           |
| < 0.2   | No        | End of Life      |

## Security Architecture & EU Cyber Resilience Act (CRA) Alignment

`dtnpm-core` implements the shared data-plane and Identity/Access Management (IAM) foundations for the `dtn-postmaster` Bundle Protocol v7 (RFC 9171) station:

- **Memory Safety & Panic-Free Production Targets**: Built in Rust (`edition = "2024"`) and checked in CI with `-D clippy::unwrap_used -D clippy::panic`.
- **BPSec Cryptography (RFC 9172 / RFC 9173)**: Ed25519 (BIB-HMAC / Ed25519 signature) and X25519 + AES-256-GCM (BCB) directional keystore (`src/security.rs`). Explicit opt-in policies (`VerifyPolicy::Warn`, `VerifyPolicy::None`) remain available for unauthenticated amateur radio interoperability or local testing, while `VerifyPolicy::Strict` rejects unverified bundles.
- **gRPC Security Gateway & Registration Ticket Gate**: `GrpcSecurityGateway` (`src/iam/grpc_guard.rs`) enforces Bearer token authentication and OPA Rego PBAC on TCP listeners and Unix Domain Sockets, and pairs with `GuardedBpaRegistration` + `GrpcRegistrationGate` so direct loopback connections bypassing the security gateway cannot hijack service/CLA/routing registration.
- **Encrypted Identity Storage**: Internal IAM user accounts (Argon2id hashes), sessions, and API tokens are stored in SQLite (`rusqlite`) or SQLCipher when encrypted storage is configured.
- **Supply Chain & VEX**: `serde_yaml` (`unsafe-libyaml`, `RUSTSEC-2024-0449`) was removed in favor of pure-Rust `yaml_serde` (`libyaml-rs`). `RUSTSEC-2026-0459` (`libsqlite3-sys` SQLite `session` extension) is documented as VEX Not Affected because `dtnpm-core` only enables `["array", "bundled", "time"]`.
- **SBOM**: Generated on every CI run in CycloneDX JSON format via `anchore/sbom-action`.

## Reporting a Vulnerability

Do **not** open a public GitHub issue for security vulnerabilities.
Report vulnerabilities privately via GitHub Security Advisories for `dtn-postmaster/dtnpm-core` or by emailing the maintainers directly. Please include:

- Component version and commit hash
- Configuration flags (`auth.mode`, `grpc.auth.enabled`, `verify_policy`, etc.)
- Minimal proof-of-concept or reproduction steps

We aim to acknowledge reports within 72 hours and coordinate a fix before public disclosure.
