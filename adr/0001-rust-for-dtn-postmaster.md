# ADR 0001: Rust and Hardy BPv7 Foundation for `dtnpm-core`

- **Status**: Accepted
- **Scope**: `dtnpm-core`

## Context
Amateur radio DTN deployments operate on resource-constrained single-board computers (Raspberry Pi, portable transceivers) over lossy RF links and untrusted relays. The shared library crate needs memory safety, async I/O without GC pauses, and strict standards compliance with RFC 9171 (BPv7).

## Decision
Build `dtnpm-core` in Rust (`edition = "2024"`) atop Rick Taylor's `hardy-bpa`, `hardy-bpv7`, `hardy-eid-patterns`, and `hardy-proto` crates. Enforce `-D warnings -D clippy::unwrap_used -D clippy::panic` on all library and binary targets to guarantee panic-free packet/bundle handling. Provide unified `BpaClient` / `LocalBpaClient` / `GrpcBpaClient` abstractions (`src/bpa_client.rs`) so services and web UI modules work transparently standalone or remotely over gRPC.

## Consequences
- Zero buffer overflows or use-after-free bugs in shared storage, routing, inspection, and IAM code.
- Bounded memory payload inspection (`bundle_inspector.rs`: 64 KiB UTF-8 prefix and `<= 256 KiB` JSON parsing cap) avoids UI/API OOM on large media bundles.
