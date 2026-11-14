# Agent Guide — `dtnpm-core`

## 🎯 Mission
Fournir les briques fondatrices et partagées de l'écosystème DTN Postmaster : configuration unifiée (`HamConfig`), persistance locale SQLite (`internal_storage`), gestionnaire de couches de convergence (`cla_manager`), suivi des services (`service_tracker`), passerelle de sécurité gRPC (`iam::grpc_guard`), contrôle d'accès PBAC, keystore BPSec (RFC 9172) et abstractions clientes du BPA (`BpaClient`).

---

## 🛡️ Référentiels et Exigences de Sécurité

### 1. Cyber Resilience Act (CRA)
- **Sécurité par défaut (Secure-by-Default)** :
  - Aucune API ou service ne doit exposer d'interface non authentifiée par défaut.
  - La barrière d'enregistrement gRPC (`GrpcRegistrationGate` / `GuardedBpaRegistration`) empêche tout contournement ou condition de course TOCTOU lors du démarrage du serveur BPA.
- **Gestion des vulnérabilités & VEX** :
  - Dépendances auditées via `cargo-audit` et `cargo-deny`.
  - Le fichier `.cargo/audit.toml` consigne la déclaration VEX `not_affected` pour `RUSTSEC-2026-0459` (extension SQLite `session` non compilée/inutilisée).
  - Les dépendances YAML utilisent `yaml_serde` (remplaçant `serde_yaml` et `unsafe-libyaml`).
  - Workflows GitHub Actions avec permissions minimales `permissions: contents: read` et actions épinglées par SHA-1 complet à 40 caractères.
- **Politique de sécurité** : Tenue à jour dans [SECURITY.md](SECURITY.md).

### 2. OWASP & Contrôle d'Accès
- **Isolation des accès gRPC & UNIX** :
  - Authentification obligatoire par jeton Bearer ou socket UNIX locale dédiée.
  - Les jetons sont résolus via `--token-file` / `DTN_HDY_TOKEN_FILE` sans transit en clair dans la table des processus.
- **PBAC (Policy-Based Access Control)** :
  - Politiques d'autorisation évaluées via le moteur Rego (`regorus`), avec gestion stricte des contextes et rôles (`operator`, `admin`).
- **BPSec (RFC 9172)** :
  - Vérification cryptographique stricte par défaut : un bundle non signé ou avec clé manquante ne doit pas être validé sous `VerifyPolicy::Strict`.

---

## 🦀 Standards d'Ingénierie Rust

1. **Règle Zéro Panic / Zéro Unwrap** :
   - Tout le code sous `src/` doit être 100% exempt de `.unwrap()`, `.expect()` et de `panic!`.
   - Utiliser `?`, `thiserror`, et des conversions sûres.
   - Validation stricte : `-D warnings -D clippy::unwrap_used -D clippy::panic`.
2. **Architecture Decision Records (ADRs)** :
   - Toute décision d'architecture doit être documentée sous `adr/` et indexée dans [adr/README.md](adr/README.md).

---

## ⚡ Commandes Critiques de Vérification

- `cargo fmt --all -- --check`
- `cargo clippy --offline --workspace --lib --bins -- -D warnings -D clippy::unwrap_used -D clippy::panic`
- `cargo test --offline --all-features`
- `./scripts/check-security.sh --strict`
- `./scripts/check-coverage.sh --summary-only`
