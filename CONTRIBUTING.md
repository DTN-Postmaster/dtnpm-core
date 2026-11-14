# Guide de Contribution — `dtnpm-core`

Ce guide présente les règles de contribution, standards d'ingénierie et bonnes pratiques applicables au dépôt `dtnpm-core`.

---

## 1. Principes Fondamentaux

- **Zéro Panic / Zéro Unwrap** : Aucun appel `.unwrap()` ou `.expect()` en code de production (`--lib`).
- **Sécurité dès la conception (Security-by-Design & CRA)** :
  - Tout secret doit être protégé (droits `0600`, pas de secrets dans `cmdline`).
  - La sécurité gRPC repose sur la barrière d'enregistrement sécurisée et les jetons Bearer.
- **Documentation et Traçabilité (ADR)** :
  - Tout ajout ou modification d'architecture fait l'objet d'un fichier ADR sous `adr/` et est indexé dans `adr/README.md`.

---

## 2. Validation Avant Soumission

Toute contribution doit passer avec succès :
```bash
cargo fmt --all -- --check
cargo clippy --offline --workspace --lib --bins -- -D warnings -D clippy::unwrap_used -D clippy::panic
cargo test --offline --all-features
./scripts/check-security.sh --strict
```
