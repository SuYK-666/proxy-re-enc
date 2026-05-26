# Experiment Result Report

## Measured Results

| Evidence | Observed conclusion |
| --- | --- |
| E01 | secure envelope 正确性和上下文拒绝通过；每个尺寸 30 次 |
| E02 | RSA/ECC baseline 各尺度每组 100 次；确定性 dataset manifest 与 p50/p95/p99/stddev 均保留 |
| E03 | chunked AEAD 每个规模 30 次覆盖至 100 MB；100 MB 严格 `<20%` heap gate 由 summary 判定；10 MB 参考范围未满足时明确报告 |
| E06 | 被撤销用户旧包 `INVALIDATED`，remaining recipient 新包 `ACTIVE`，version 2 |
| E08 | audit tamper detection 数据已保存；当前代码新增 Ed25519 checkpoint 验证 |
| E13 | `2/3` 与 `3/5` signed-share 路径各 30 次样本；不足阈值拒绝数据已保存 |
| E15 | 五种确定性 plaintext 分布各 30 次；结果解释分布对 AEAD 测量的影响边界 |

## Interpretation Boundary

已保留的 E02 CSV 是 RSA/ECC baseline 测量，不将其陈述为生产密码安全证明。
新增 Ed25519 conversion/audit proof 与 threshold signed-share 代码将在本次
最终 `verify-all` 运行中由单元/集成测试验证；需要新性能统计时必须另存新 raw
文件，不覆盖旧 raw 的含义。KMS/HSM、OIDC、不可篡改外部锚定和多实例
数据库装配不属于当前实测结论。

原始文件位于 [`../reports/raw`](../reports/raw)，已有逐项解释位于
[`../reports/summary`](../reports/summary)。
