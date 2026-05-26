# Security Regression

## Required Checks

| Control | Tests |
| --- | --- |
| baseline/profile isolation | `CryptoProfileGuardTest`, `ApiIntegrationTest` |
| ECC baseline collusion boundary | `EccCollusionBoundaryTest` |
| AAD/package tamper | `CryptoProviderTest` (12 context fields), `CapsuleContextBindingTest`, `PackageVerifierTest`, `TamperDetectionTest` |
| streaming chunk integrity | `AesGcmChunkedDecryptorTest` (modify/delete/reorder/AAD replacement) |
| conversion proof | `ConversionProofServiceTest` |
| revoke/rotation | `ReKeyShareLifecycleTest`, `KeyLifecycleServiceTest` |
| nonce collision/restart | `AesGcmNonceManagerTest` |
| threshold shares | `ThresholdSecretSharingTest`, `ThresholdReEncryptionServiceTest` |
| authorization/proxy | `UnauthorizedAccessTest`, `ProxyNodeServiceTest` |
| audit chain/signature | `AuditHashChainTest`, `AuditProofServiceTest` |
| sensitive output | `LogSanitizerTest` |

The full attack-to-test mapping is maintained in
[`../security/attack-test-matrix.md`](../security/attack-test-matrix.md).

## Run

```powershell
mvn test
powershell -ExecutionPolicy Bypass -File scripts/verify-all.ps1
```

`verify-all` 进一步执行 `mvn verify` 静态/覆盖率门禁、保留 raw 实验输出、
执行性能 smoke budget 和生成最终复核报告。
