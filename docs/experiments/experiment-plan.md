# Experiment Plan

本入口对应验收 E-001 至 E-010；已运行实验的具体参数与输出映射见
[experiment-design.md](experiment-design.md)。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run-all-experiments.ps1
```

| Requirement experiment | Current executable evidence | Status boundary |
| --- | --- | --- |
| E-001 correctness | `e01-secure-envelope-correctness.csv`, 30 samples/size | measured |
| E-002 performance | `e02-algorithm-benchmark.csv`, `dataset-manifest.json`, 100 samples/group | RSA/ECC baseline measured |
| E-003 context tamper | E01/E04 and `CryptoProviderTest` | 12 canonical AAD fields rejected |
| E-004 revoke/rotation | `e06-revocation-results.json`, lifecycle tests | owner-side rotation |
| E-005 nonce | `e07-nonce-results.json`, nonce tests | single-process/file plus schema |
| E-006 audit | `e08-audit-tamper-results.json`, Ed25519 tests | external anchor pending |
| E-007 authorization | API/security tests | measured |
| E-008 threshold | `e13-threshold-results.csv`, 30 signed-share samples/config | experimental |
| E-009 streaming | `e03-chunked-aead-results.csv`, `e03-chunk-integrity-results.json` | 30 runs/size to 100 MB; observed heap plus four integrity negatives |
| E-010 idempotency | `IdempotencyServiceTest`, `ApiIntegrationTest` | HTTP replay implemented; multi-instance persistence is deployment-scoped |
| Dataset distributions | `e15-dataset-distribution-results.csv`, `dataset-manifest.json` | five deterministic types, 30 samples/type |

原始数据文件由 runner 写入，不能以规划文档中的目标区间替换。
