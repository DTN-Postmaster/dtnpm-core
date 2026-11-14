# dtnpm-core

Core traits, configuration, storage, RF pacing, BPsec keystore, and BPA transport clients for **DTN Postmaster** (`dtnpm`).

## Overview

`dtnpm-core` provides the shared domain logic used across DTN Postmaster CLAs, WebUI plugins, CLI tools, and assembler profiles:

- **Configuration (`config`)**: Unified YAML/TOML/JSON configuration (`HamConfig`, `ClaConfig`, `ClaType`, `RouteConfig`) with amateur radio callsign defaults (`dtn://<callsign>/`).
- **BPA Transports (`bpa_client`, `mock_bpa`)**: Unified `BpaClient` trait backed by `LocalBpaClient` (`transport-local`), `GrpcBpaClient` (`transport-grpc`), and `MockBpa` for isolated unit/module testing.
- **Persistence (`internal_storage`)**: Shared SQLite `Arc<Mutex<Connection>>` (`rusqlite` `0.40`) supporting module schema migrations, application quotas, and `spawn_expiration_reaper`.
- **Routing, CLA & Service Tracking (`routing`, `cla_manager`, `service_tracker`)**: Dynamic route management, peer status tracking, SSE event broadcasting, and BPA service registration.
- **BPsec Security (`security`, `cli_security`)**: Directional HMAC-SHA256 integrity/signing keystore and BPv7 verification policies (`warn`, `strict`).
- **Contact Coordination (`coordinator`, `pacing`)**: Cron-based and one-shot RF contact schedules plus pacing utilities.
- **Protocol & CLI Utilities (`basket`, `bundle_inspector`, `log_buffer`)**: BPv7 bundle inspection, Basket protocol types, and circular log buffering.

## Features

- `transport-local`: Enable direct in-process `LocalBpaClient`.
- `transport-grpc`: Enable remote gRPC `GrpcBpaClient` via `hardy-proto`.
- `instrument`: Enable `tracing/attributes` and Hardy instrumentation hooks.
- Default features: `["transport-local", "transport-grpc"]`.

## Build and Test

Requires sibling checkouts of `../../hardy/*` as referenced in `Cargo.toml`.

```bash
cargo test
```

## License

Dual-licensed under the Apache License, Version 2.0 or the MIT License. See [LICENSE.md](LICENSE.md).
