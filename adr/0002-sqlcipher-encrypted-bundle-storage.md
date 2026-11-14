# ADR 0002: Internal SQLite Storage & Key-Protected IAM Persistence

- **Status**: Accepted
- **Scope**: `dtnpm-core` (`src/internal_storage.rs`, `src/bundle_inspector.rs`)

## Context
`dtnpm-core` persists station configuration state, module schemas (shared SQLite `internal_storage`), and IAM credentials (Argon2id password hashes, session tokens, API token digests) alongside Hardy's bundle store.

## Decision
Use bundled `rusqlite` (SQLite) without enabling the optional `session` extension, eliminating exposure to SQLite session-extension vulnerabilities (`RUSTSEC-2026-0459` VEX: Not Affected). Store local user passwords exclusively as Argon2id PHC hashes and session/API tokens as salted/hashed digests with strict foreign-key and WAL integrity.

## Consequences
- Single-file ACID storage safe for sudden power loss on portable amateur radio stations.
- Clear VEX traceability under the EU Cyber Resilience Act.
