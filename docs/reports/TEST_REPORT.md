# ReKeyShare Test Report

Date: 2026-05-19
Runtime used in this workspace: Java 25.0.2 via `javac/java`; project target remains Java 17 LTS.

## Verification Summary

```text
javac main compile: PASS
javac test compile: PASS
TestSuiteRunner: Tests run: 50, Failures: 0
DemoApplication: PASS
SelfTestApplication: PASS
BenchmarkApplication: PASS
```

## Latest Security Coverage

| Area | Evidence |
|---|---|
| Signed token auth | Protected API rejects missing bearer token |
| RSA/ECC API | RSA grant flow and ECC recipient-share grant flow pass |
| BOLA/IDOR | Charlie cannot read Alice data or Bob package |
| Revocation | Revoked grant blocks proxy use and packages are invalidated |
| Action policy | Re-encrypt/download/decrypt/preview checks are separated |
| Grant context evidence | Tampered `grantContextHash` is rejected |
| Capsule context | Wrong dataId/policy context fails |
| ECC recipient share | Wrong recipient, challenge, and signature are rejected |
| Audit chain | Tamper detection and chain verification pass |
| Audit proof | Merkle root and demo signature are exported |
| Snapshot persistence | JSON snapshot hash export, import-check, and repository manifest pass |
| Benchmark summary | CSV is parsed into structured grouped JSON |

## Reports

- `docs/reports/performance-results.csv` is the raw benchmark source of truth.
- `docs/reports/performance-summary.md` is generated from the CSV.
- `docs/reports/api-attack-matrix.md` lists API attack cases.
- `docs/design/threat-model.md` and `docs/design/security-boundary.md` define security assumptions and limits.

## Remaining Production Boundary

RSA/ECC PRE algorithms are teaching prototypes. The production path should replace them through the `PreScheme` interface with reviewed PRE/HPKE/threshold PRE libraries and replace memory+snapshot storage with H2/SQLite/JPA or another durable database.
