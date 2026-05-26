# Final Verification

- Commit: `9189d850fc483ae4f9f58f3b4fef1caae2b1a6e8`
- Executed at: `2026-05-26T19:46:46.0409877+08:00`
- Duration seconds: `166.95`
- Java: `java version "22.0.2" 2024-07-16`
- Build/unit/integration/security/static-quality gates (`mvn verify`): `PASS`
- Security boundary gate: `PASS`
- Reproducible experiment runner: `PASS`
- Documentation links and performance budget: `PASS`

Raw experiment evidence is preserved under `docs/reports/raw/`; interpreted summaries are under `docs/reports/summary/`.
Deployment-scoped integrations (KMS/HSM, OIDC/mTLS, WORM anchor, durable multi-instance runtime wiring) remain explicit boundaries.
