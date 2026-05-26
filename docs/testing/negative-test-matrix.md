# Negative Test Matrix

| 风险类别 | Case | 预期 | 证据 |
| --- | --- | --- | --- |
| 未认证 | 无 bearer token 调用受保护 API | 401 + traceId | `ApiIntegrationTest` |
| 越权 | Charlie 猜测 Bob package | 403 | `ApiIntegrationTest` |
| Production 明文 | 调用 demo plaintext route | 403 | `ApiIntegrationTest` |
| Package 篡改 | ciphertext/AAD/capsule/policy/manifest 替换 | `PACKAGE_INVALID` | `PackageVerifierTest`, E04 |
| Chunk 篡改 | 中间 ciphertext chunk bit flip | 拒绝并定位 index | `AesGcmChunkedDecryptorTest` |
| Scope 绕过 | 跨 grant/data/key version/policy 使用 rekey | 拒绝 | `ScopedReEncryptionKeyTest` |
| ABAC | tenant/role/purpose/time/count/proxy 不满足 | deny | `PolicyEvaluatorTest` |
| Proxy | revoked/quota/scheme 不满足 | 拒绝 | `ProxyNodeServiceTest` |
| 状态 | 从终态恢复为活动态 | `INVALID_STATE_TRANSITION` | `StateTransitionGuardTest` |
| Threshold | 少于 k 份 share | 恢复失败 | `ThresholdSecretSharingTest`, E13 |

安全关键拒绝路径的自动化用例由既有 negative/scenario/API 测试与新增矩阵共同组成；raw 结果由实验脚本生成并保留。
