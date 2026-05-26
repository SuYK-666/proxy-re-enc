# 测试计划

| 层级 | 目标 | 代表测试/证据 |
| --- | --- | --- |
| 算法正确性 | RSA/ECC baseline 与 secure envelope 恢复 DEK | `RsaPreSchemeTest`, `EccPreSchemeTest`, `CryptoProviderTest`, E01 |
| 完整性 | AAD/capsule/package/chunk 篡改拒绝 | `PackageVerifierTest`, `AesGcmChunkedDecryptorTest`, E04 |
| 策略与撤销 | 过期、限次、撤销、作用域拒绝 | `AuthorizationPolicyTest`, `ScopedReEncryptionKeyTest`, `ReKeyShareLifecycleTest` |
| API 边界 | production 无明文、错误追踪、越权/重放/畸形输入拒绝 | `ApiIntegrationTest`, E11 |
| 并发/恢复 | 限次授权无超发且 JDBC 状态可恢复 | `ApiIntegrationTest.concurrentDownloadsCannotExceedAccessLimit`, `JdbcGovernanceRepositoryTest`, E10 |
| 代理 | 禁用、配额、scheme 限制 | `ProxyNodeServiceTest` |
| 审计 | hash-chain/proof 篡改检查与首次异常定位 | `AuditHashChainTest`, `AuditProofServiceTest`, E08 |
| 扩展实验 | 100 MB 流式与 threshold prototype | E03、E13 raw/summary |

复现命令：

```powershell
mvn test
powershell -ExecutionPolicy Bypass -File scripts/run-all-experiments.ps1
```

CI 使用 Java 17 执行 `mvn verify`、安全边界脚本和实验 runner，并保留报告 artifacts。
