# Contributing

Thanks for taking time to improve ReKeyShare.

## Scope and Boundaries

- This repository is a backend security prototype. RSA/ECC PRE are teaching baselines, not production security claims.
- Production deployments must replace baseline schemes with reviewed libraries and keep private keys client-side or in KMS/HSM.

## Development Setup

- JDK 17+
- Maven 3.9+

Recommended workflow:

1. Run unit tests:

   mvn test

2. Run experiments (evidence outputs):

   powershell -ExecutionPolicy Bypass -File scripts\run-all-experiments.ps1

3. Run quality gates:

   powershell -ExecutionPolicy Bypass -File scripts\check-security-boundary.ps1
   powershell -ExecutionPolicy Bypass -File scripts\check-performance-budget.ps1
   powershell -ExecutionPolicy Bypass -File scripts\check-doc-links.ps1

## Evidence and Documentation

- If you change crypto, security, storage, or API behavior, update:
  - docs/traceability-matrix.md
  - the related design/security docs under docs/
  - reports/summary to reflect updated experiment outputs
- Keep raw outputs in docs/reports/raw. Do not delete historical evidence without noting why.

## Security and Data Handling

- Never commit plaintext, DEK material, private keys, or real user data.
- Sanitize logs before writing to audit or output. Use LogSanitizer where applicable.
- Do not add demo endpoints to the production profile.

## Pull Request Checklist

- [ ] Tests pass (mvn test)
- [ ] Experiments regenerated if behavior changed
- [ ] Security boundary remains intact (no plaintext in production responses)
- [ ] Docs and traceability updated
