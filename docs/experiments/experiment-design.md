# 实验设计

## 运行方式

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run-all-experiments.ps1
```

Linux/CI:

```sh
sh scripts/run-all-experiments.sh
```

runner 输出 `docs/reports/raw/*` 与 `docs/reports/summary/*`，nonce registry 定向到 `target/experiment`。

| 编号 | 实验 | 参数 | 严格通过条件 | 输出 |
| --- | --- | --- | --- | --- |
| E01 | secure envelope 正确性 | 1KB/100KB/1MB/10MB，各 30 rounds | 恢复与非授权拒绝均 100% | `e01-secure-envelope-correctness.csv` |
| E02 | RSA/ECC baseline benchmark | 1KB/100KB/1MB/10MB，warmup=20，rounds=100 | 成功率 100%，汇报 p50/p95/p99 | `e02-algorithm-benchmark.csv` |
| E03 | chunked AEAD | 1/10/100 MB，各 30 rounds，chunk=128 KiB，`-Xmx12m` | 全部验证通过；记录 heap；4 种完整性负例拒绝 | `e03-chunked-aead-results.csv`, `e03-chunk-integrity-results.json` |
| E04 | V2 篡改 | ciphertext/AAD/capsule/policy/manifest | 检测率 100% | `e04-package-tamper-results.json` |
| E05 | ABAC 负向矩阵 | 50 cases | 拒绝率 100%，server error 0 | `e05-negative-policy-matrix.json` |
| E06 | 撤销与轮换 | Bob 旧包、Carol 新包、key version 2 | 旧包 INVALIDATED，新包 ACTIVE，新版本生效 | `e06-revocation-results.json` |
| E07 | Nonce 与重放边界 | 100 unique + duplicate + 100-thread JUnit | 重复拒绝 100%，并发仅一次接受 | `e07-nonce-results.json` |
| E08 | 审计篡改 | delete/modify/reorder/insert | 检测率 100% 且记录首次 mismatch | `e08-audit-tamper-results.json` |
| E09 | 并发访问限次 | 100 concurrent，maxAccess=1/3/10 | 超发数 0 | `e09-concurrency-results.csv` |
| E10 | 持久化与恢复 | JDBC 重启 + 100 concurrent | 状态/审计恢复、孤儿 0、超发 0 | `e10-persistence-recovery-results.json` |
| E11 | API 鲁棒性 | 104 malformed/fuzz cases | 4xx 100%，5xx 0 | `e11-api-robustness-results.json` |
| E12 | 代理最小知识 | 密文视图与脱敏日志扫描 | plaintext/DEK/private key 泄露均 0 | `e12-proxy-minimum-knowledge-results.json` |
| E13 | threshold prototype | 2-of-3、3-of-5 | `<k` 失败且 `>=k` 成功 | `e13-threshold-results.csv` |
| E14 | 性能回归门禁 | retained baseline versus current p95 | p95 回归不超过 25%，正确性失败 0 | `e14-performance-gate-results.json` |
| E15 | 数据分布影响 | 5 distributions，1 MB，各 30 rounds | 全部恢复成功，保留输入 hash 与耗时 | `e15-dataset-distribution-results.csv` |

每个 summary 记录 commit、JDK、OS、运行时间及 raw 链接；环境总览见
`raw/experiment-environment.json`。E06/E08/E10-E12/E14 由
`ComplianceExperimentApplication` 生成，E10 明确测量 JDBC 治理 adapter，
而不是把默认内存 API 装配描述成生产持久化。
