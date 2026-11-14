# Architecture Decision Records — `dtnpm-core`

This directory documents the core architectural and cybersecurity decisions for **`dtnpm-core`**, extracted from the monolithic `dtnpm` repository into the shared library crate.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-rust-for-dtn-postmaster.md) | Rust and Hardy BPv7 Foundation for `dtnpm-core` | Accepted |
| [0002](0002-sqlcipher-encrypted-bundle-storage.md) | Internal SQLite Storage & Key-Protected IAM Persistence | Accepted |
| [0003](0003-bpsec-ed25519-and-x25519-aes256gcm.md) | BPSec Ed25519 BIB & X25519+AES-256-GCM BCB with Explicit Policy Modes | Accepted |
| [0004](0004-contact-plan-scheduling-and-yaml-serde.md) | Contact Plan Scheduling, Coordinator Backoff, and Pure-Rust `yaml_serde` | Accepted |
| [0005](0005-iam-grpc-security-gateway-and-pbac.md) | IAM gRPC Security Gateway, Rego PBAC, and Loopback Registration Gate | Accepted |
