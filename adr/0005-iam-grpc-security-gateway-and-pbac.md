# ADR 0005: IAM gRPC Security Gateway, Rego PBAC, and Loopback Registration Gate

- **Status**: Accepted
- **Scope**: `dtnpm-core` (`src/iam/grpc_guard.rs`, `src/iam/mod.rs`, `src/config/mod.rs`)

## Context
Hardy's `GrpcServer` exposes gRPC registration RPCs (`Application`, `Service`, `Cla`, `RoutingAgent`) without built-in authentication. When `dtnpm` wraps Hardy's server behind `GrpcSecurityGateway` on a public address while binding the raw Hardy gRPC server on `127.0.0.1:<ephemeral>`, any unauthenticated local process on the same host could connect directly to `127.0.0.1:<ephemeral>` and register malicious services or CLAs, bypassing Bearer tokens and OPA Rego PBAC (`DTNPM-01`).

## Decision
Introduce `GrpcSecurityGateway`, OPA Rego PBAC policy evaluation (`regorus`), and a short-lived single-use `GrpcRegistrationGate` paired with `GuardedBpaRegistration`:
- `GrpcSecurityGateway` issues a 10-second `GrpcRegistrationTicket` per RPC kind (`Application`, `Service`, `Cla`, `Routing`) only after authenticating the caller and passing `PolicyEngine` PBAC checks.
- `GuardedBpaRegistration` intercepts `register_application`, `register_service`, `register_cla`, and `register_routing_agent` on the internal Hardy `GrpcServer` and rejects requests unless a valid active ticket is present.
- Operators running purely local/isolated development environments may still explicitly disable gRPC auth (`[grpc.auth].enabled = false`).

## Consequences
- Local unauthenticated processes cannot bypass `GrpcSecurityGateway` to spoof CLAs, services, or routing agents over loopback.
- Unix Domain Sockets (`0660`) and Bearer token authentication + Rego PBAC are enforced end-to-end when `[grpc.auth].enabled = true`.
