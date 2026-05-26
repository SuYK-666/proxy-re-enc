# 文档索引

本目录是 ReKeyShare 后端安全升级后的证据入口。`RSA_PRE` 与 `ECC_PRE` 始终是教学/对照
baseline；`SECURE_ENVELOPE_V1` 是使用 JCA 原语实现的直接接收方封装候选路径，
不宣称具备 PRE 代理转换语义。

| 类别 | 文档 |
| --- | --- |
| 架构 | [system-architecture.md](architecture/system-architecture.md)、[state-machines.md](architecture/state-machines.md) |
| 算法 | [provider-contract.md](algorithms/provider-contract.md)、[rsa-pre-baseline.md](algorithms/rsa-pre-baseline.md)、[ecc-pre-baseline.md](algorithms/ecc-pre-baseline.md)、[secure-envelope-provider.md](algorithms/secure-envelope-provider.md)、[streaming-aead.md](algorithms/streaming-aead.md)、[threshold-prototype.md](algorithms/threshold-prototype.md) |
| 安全 | [security-boundary.md](security/security-boundary.md)、[threat-model.md](security/threat-model.md)、[abac-policy-model.md](security/abac-policy-model.md)、[revocation-semantics.md](security/revocation-semantics.md)、[rekey-scope.md](security/rekey-scope.md)、[access-counter.md](security/access-counter.md)、[log-redaction.md](security/log-redaction.md) |
| 格式/API | [v2.md](package-format/v2.md)、[api-design.md](api/api-design.md)、[error-model.md](api/error-model.md)、[error-codes.md](api/error-codes.md)、[idempotency.md](api/idempotency.md)、[security-controls.md](api/security-controls.md) |
| 测试/实验 | [test-plan.md](testing/test-plan.md)、[negative-test-matrix.md](testing/negative-test-matrix.md)、[experiment-design.md](experiments/experiment-design.md)、[dataset-design.md](experiments/dataset-design.md)、[`reports/raw`](reports/raw)、[`reports/summary`](reports/summary) |
| 运行 | [container-hardening.md](ops/container-hardening.md)、[ci-quality-gates.md](ops/ci-quality-gates.md)、[observability.md](ops/observability.md) |
| 质量 | [quality-gates.md](quality/quality-gates.md) |
| 存储 | [repository-design.md](storage/repository-design.md)、[schema.md](storage/schema.md)、[database-migration.md](database-migration.md) |
| 复核补充 | [state-machines.md](state-machines.md)、[multi-tenant-isolation.md](multi-tenant-isolation.md)、[secure-coding.md](secure-coding.md) |
| 追踪 | [traceability-matrix.md](traceability-matrix.md) |
| 验收指定入口 | [architecture.md](architecture.md)、[algorithm-spec.md](crypto/algorithm-spec.md)、[security-boundary.md](crypto/security-boundary.md)、[envelope-scheme.md](crypto/envelope-scheme.md)、[context-binding.md](crypto/context-binding.md)、[threshold-re-encryption.md](crypto/threshold-re-encryption.md)、[authorization-matrix.md](api/authorization-matrix.md)、[revocation-and-rotation.md](revocation-and-rotation.md)、[audit-proof.md](audit-proof.md)、[data-model.md](data-model.md)、[experiment-plan.md](experiments/experiment-plan.md)、[result-report.md](experiments/result-report.md)、[security-regression.md](testing/security-regression.md)、[deployment.md](deployment.md) |
