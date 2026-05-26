# Traceability Matrix

本矩阵将指导文档的核心整改项映射至当前代码、测试与实验/文档证据。`implemented` 表示仓库内存在可执行实现与验证；生产外部系统接入边界另列说明。

| 需求 | 状态 | 代码 | 测试/实验 | 文档 |
| --- | --- | --- | --- | --- |
| M01/F01 baseline 隔离与 provider | implemented | `crypto/provider/*` | `CryptoProviderTest` | `algorithms/provider-contract.md` |
| M02 RSA baseline 风险标注 | implemented | `BaselineRsaProvider`, `RsaPreScheme` | `RsaPreSchemeTest`, E02 | `algorithms/rsa-pre-baseline.md` |
| M03 ECC 实验边界/非法点 | implemented | `BaselineEccProvider`, `P256Curve` | `EccPreSchemeTest` | `algorithms/ecc-pre-baseline.md` |
| M04 scoped rekey | implemented | `ScopedReEncryptionKey`, `ProxyReEncryptionService` | `ScopedReEncryptionKeyTest` | `security/rekey-scope.md` |
| M05/F04 package V2 | implemented | `SharedPackageV2`, `PackageManifest`, `PackageVerifier` | `PackageVerifierTest`, E04 | `package-format/v2.md` |
| M06 流式验证 | implemented | `AesGcmChunkedDecryptor`, `MerkleChunkTree` | `AesGcmChunkedDecryptorTest`, E03 | `algorithms/streaming-aead.md` |
| M07 nonce 防复用 | implemented (single instance/file + DB schema) | `AesGcmNonceManager`, `schema.sql` | `AesGcmNonceManagerTest` | `security/nonce-management.md` |
| M08/F05 ABAC | implemented policy core | `security/policy/*` | `PolicyEvaluatorTest` (10 permit/10 deny) | `security/abac-policy-model.md` |
| M09/F06 撤销/轮换 | implemented | `RevocationService`, `StateTransitionGuard` | `ReKeyShareLifecycleTest` | `security/revocation-semantics.md` |
| M10/F07 密钥边界 | implemented production boundary/model | `UserService.registerPublicOnlyUser`, `KeyManagementService`, `KeyVersion` | `SecurityBoundaryServiceTest`, production API test | `security/key-lifecycle.md` |
| M11/F09 audit proof | implemented | `AuditProofService`, `JdbcAuditRepository` | `AuditProofServiceTest`, `JdbcAuditRepositoryTest` | `security/audit-proof-format.md` |
| M12 proxy 治理 | implemented | `ProxyNode`, `ProxyNodeService` | `ProxyNodeServiceTest` | `security/proxy-minimum-knowledge.md` |
| M13 API error/限流/幂等 | implemented | `ReKeyShareApplication` | `ApiIntegrationTest`, E11 | `api/error-model.md`, `api/security-controls.md` |
| M14/F08 repository | implemented adapter; runtime wiring bounded | `schema.sql`, `JdbcAuditRepository`, `JdbcGovernanceRepository` | `JdbcAuditRepositoryTest`, `JdbcGovernanceRepositoryTest`, E10 | `storage/repository-design.md` |
| M15/F10 benchmark runner | implemented | `BenchmarkApplication`, `EvidenceExperimentApplication` | E01/E02/E03/E04/E13 | `experiments/experiment-design.md` |
| M16/F11 攻击模拟 | implemented matrix coverage | security/API tests | E04 + `negative/*` | `testing/negative-test-matrix.md` |
| M17 Docker 加固 | implemented | `Dockerfile`, `docker-compose.yml`, `HealthCheckApplication` | container build in deployment/CI | `ops/container-hardening.md` |
| M18 CI/SBOM | implemented configuration | `.github/workflows/backend-ci.yml`, `pom.xml` | CI `mvn verify` | `ops/ci-quality-gates.md` |
| M20/F03 threshold 原型 | implemented experimental | `crypto/threshold/*` | `ThresholdSecretSharingTest`, E13 | `algorithms/threshold-prototype.md` |
| M21 并发限次 | implemented in-memory + JDBC atomic path | API synchronized consume, `JdbcGovernanceRepository` CAS update | `concurrentDownloadsCannotExceedAccessLimit`, `JdbcGovernanceRepositoryTest`, E10 | `security/access-counter.md`, `storage/repository-design.md` |
| M22 原始数据/复现 | implemented | `scripts/run-all-experiments.*`, `ComplianceExperimentApplication` | E01-E14 `reports/raw`, `reports/summary` | `reports/report-template.md`, `experiments/experiment-design.md` |

## Production Integration Boundary

以下能力需要部署系统或外部基础设施，仓库不虚构其已上线：将 HTTP runtime 装配为 JDBC 治理 adapter 的多实例部署、ciphertext 对象存储运维、KMS/HSM 私钥托管、OIDC/mTLS、外部不可篡改 audit anchor，以及联网更新漏洞库后的发布扫描结果。
