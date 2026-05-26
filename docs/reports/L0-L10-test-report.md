# L0-L10 Test Report

Date: 2026-05-19

## Summary

| Level | Task | Result | Raw Artifacts |
|---|---|---|---|
| L0 | Build and static quality | Partial PASS: `javac` PASS; Maven tools blocked because local `mvn` is not installed | `docs/reports/raw/L0/javac-main.txt`, `docs/reports/raw/L0/mvn-test.txt`, `docs/reports/raw/L0/summary.json` |
| L1 | Crypto primitives | PASS via RSA/ECC self-test and existing crypto test coverage | `docs/reports/raw/L1/crypto-self-test-output.txt` |
| L2 | PRE workflow correctness | PASS: authorized Bob decrypts; Charlie fails; no formal plaintext response | `docs/reports/raw/L2/pre-workflow-output.txt` |
| L3 | Authentication and authorization | PASS: missing token 401; header spoof ignored; policy limit 403 | `docs/reports/raw/L3/api-authz-results.json` |
| L4 | Revocation and rotation | PASS: revoked package access 403; rotation version increments in self-test | `docs/reports/raw/L4/revocation-results.json`, `docs/reports/raw/L10/self-test-output.txt` |
| L5 | Audit integrity | PASS: normal, field tamper, delete, reorder, rewrite, checkpoint cases pass | `docs/reports/raw/L5/audit-tamper-results.json` |
| L6 | Concurrency consistency | PASS: 20 concurrent downloads with `maxDownloadCount=1` produced exactly 1 success | `docs/reports/raw/L6/concurrency-download-results.json` |
| L7 | API robustness and fuzz | PASS: invalid JSON 400; missing token 401; policy violation 403 | `docs/reports/raw/L7/api-fuzz-results.json` |
| L8 | Persistence and recovery | PASS: snapshot export and import-check hash verification succeeded | `docs/reports/raw/L8/storage-recovery-results.json` |
| L9 | Performance and pressure | PASS: benchmark generated CSV and summary with latency/throughput/success | `docs/reports/raw/L9/benchmark-output.txt`, `docs/reports/performance-results.csv`, `docs/reports/performance-summary.md` |
| L10 | End-to-end security scenario | PASS: RSA/ECC sharing, revoke, rotation, audit verification pass | `docs/reports/raw/L10/self-test-output.txt` |

## Environment Note

The local workspace has `javac 25.0.2` but no `mvn` executable. Therefore
Maven-dependent L0 gates (`mvn test`, `mvn verify`, `spotbugs:check`,
`dependency-check:check`, `jacoco:report`) are configured in `pom.xml` and CI
but could not be executed locally in this session. The raw error is preserved in
`docs/reports/raw/L0/mvn-test.txt`.

## Key Raw Results

- `docs/reports/raw/L3/api-authz-results.json`: `missingTokenStatus=401`,
  `headerSpoofRecipient=bob`, `formalResponseHasPlaintext=false`,
  `secondDownloadStatus=403`.
- `docs/reports/raw/L7/production-profile-results.json`: production profile hides demo decrypt/upload routes and rejects plaintext upload with 403.
- `docs/reports/raw/L5/audit-tamper-results.json`: all audit tamper checks are `PASS`.
- `docs/reports/raw/L6/concurrency-download-results.json`: `success=1`, `denied=19`.
- `docs/reports/raw/L8/storage-recovery-results.json`: `importCheck.valid=true`.
- `docs/reports/performance-summary.md`: benchmark rows all marked `PASS`.
