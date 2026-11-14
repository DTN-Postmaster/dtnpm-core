# ADR 0004: Contact Plan Scheduling, Coordinator Backoff, and Pure-Rust `yaml_serde`

- **Status**: Accepted
- **Scope**: `dtnpm-core` (`src/coordinator/mod.rs`, `src/routing.rs`, `Cargo.toml`)

## Context
The scheduled contact coordinator drives radio links (`start_contact` / `end_contact`), and the router/coordinator parse operator contact plans and static route files (YAML and TOML). Three risks were identified:
1. Tight spin-loop CPU exhaustion when waking slightly early before `next_start` or immediately retrying a failing `start_contact`.
2. Supply-chain exposure to unmaintained C bindings via `serde_yaml` -> `unsafe-libyaml` (`RUSTSEC-2024-0449`).

## Decision
1. Add an explicit early-wakeup guard (`current_now < next_start`) and a 1-second failure cooldown backoff inside `Coordinator` (`src/coordinator/mod.rs`).
2. Replace `serde_yaml` with `yaml_serde = "0.10"` (pure-Rust `libyaml-rs`) across `dtnpm-core`, and support native `.toml` route persistence in `RouteManager` (`src/routing.rs`).

## Consequences
- Eliminates `unsafe-libyaml` and `RUSTSEC-2024-0449` completely from the dependency graph.
- Prevents CPU saturation on embedded hardware when a radio CLA is temporarily unavailable.
