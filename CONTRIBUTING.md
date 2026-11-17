# Contributing Guide — `dtnpm-core`

This guide outlines the contribution rules, engineering standards, and best practices applicable to the `dtnpm-core` repository.

---

## 1. Core Principles

- **Zero Panic / Zero Unwrap**: No `.unwrap()` or `.expect()` calls in production code (`--lib`).
- **Security-by-Design & CRA**:
  - All secrets must be protected (`0600` permissions, no secrets in `cmdline`).
  - gRPC security relies on the guarded registration gate and Bearer tokens.
- **Documentation and Traceability (ADR)**:
  - Any architectural addition or modification must be documented in an ADR file under `adr/` and indexed in `adr/README.md`.

---

## 2. Pre-Submission Validation

Every contribution must pass:
```bash
cargo fmt --all -- --check
cargo clippy --offline --workspace --lib --bins -- -D warnings -D clippy::unwrap_used -D clippy::panic
cargo test --offline --all-features
./scripts/check-security.sh --strict
```
