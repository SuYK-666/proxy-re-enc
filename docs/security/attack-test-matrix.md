# Attack Test Matrix

This matrix maps security claims to executable checks. Rows may share a test
class when one automated scenario makes several independent mutations.

| ID | Threat / Asset | Control | Test Class | Expected Result | Residual Risk |
| --- | --- | --- | --- | --- | --- |
| AT-01 | Missing bearer token / API | token guard | `ApiIntegrationTest` | `UNAUTHENTICATED` | external IAM not wired |
| AT-02 | Plaintext upload in production / content | profile route guard | `ApiIntegrationTest` | `DEMO_ONLY_API_DISABLED` | demo deliberately exposes fixture |
| AT-03 | Baseline selection in production / keys | crypto profile guard | `ApiIntegrationTest` | `CRYPTO_PROFILE_NOT_ALLOWED` | reviewed PRE not provided |
| AT-04 | RSA provider in standard profile / suite | crypto profile guard | `CryptoProfileGuardTest` | rejected | baseline remains in demo |
| AT-05 | ECC provider in standard profile / suite | crypto profile guard | `CryptoProfileGuardTest` | rejected | baseline remains in demo |
| AT-06 | Cross-tenant AAD / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | identity source deployment scoped |
| AT-07 | Cross-object AAD / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | none in envelope core |
| AT-08 | Owner replacement / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | none in envelope core |
| AT-09 | Recipient replacement / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | none in envelope core |
| AT-10 | Grant replacement / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | direct owner upload uses sentinel grant |
| AT-11 | Policy replacement / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | policy language is bounded |
| AT-12 | Key-version rollback / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | offline plaintext cannot be revoked |
| AT-13 | Suite substitution / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | algorithm migrations need operations |
| AT-14 | Proof issuer substitution / envelope | canonical AAD | `CryptoProviderTest` | decrypt fails | signer provisioning deployment scoped |
| AT-15 | Ciphertext bit flip / content | AES-GCM | `TamperDetectionTest` | authentication fails | none in primitive path |
| AT-16 | Chunk modification / large object | chunk AEAD/Merkle | `AesGcmChunkedDecryptorTest` | reject altered chunk | storage availability out of scope |
| AT-17 | Capsule algorithm swap / DEK | scheme type check | `PreSchemeNegativeTest` | rejected | demo suite security limited |
| AT-18 | Package ciphertext swap / package | manifest | `PackageVerifierTest` | `PACKAGE_INVALID` | none in validator |
| AT-19 | Package version injection / package | version gate | `PackageVerifierTest` | `PACKAGE_INVALID` | migration tooling bounded |
| AT-20 | Grant context swap / package | grant context hash | `PolicyActionAuthorizationTest` | `AAD_MISMATCH` | none in access path |
| AT-21 | Unauthorized recipient / package | object authorization | `ApiIntegrationTest` | `ACCESS_DENIED` | identifier leakage rate limited only |
| AT-22 | Wrong grant owner / grant | ownership check | `ApiIntegrationTest` | `ACCESS_DENIED` | external IAM required |
| AT-23 | Expired grant / grant | policy expiry | `AuthorizationPolicyTest` | denied | clock authority deployment scoped |
| AT-24 | Revoked grant replay / grant | revoke status | `AuthorizationPolicyTest` | `GRANT_REVOKED` | downloaded plaintext cannot be recalled |
| AT-25 | Old package after hard revoke / package | lifecycle invalidation | `KeyLifecycleServiceTest` | inaccessible | rewrap is owner initiated |
| AT-26 | Re-encrypt quota bypass / grant | scoped counter | `ScopedReEncryptionKeyTest` | rejected | distributed counter needs DB |
| AT-27 | Revoked proxy / transformation | proxy state | `ProxyNodeServiceTest` | `PROXY_INACTIVE` | anomaly scoring bounded |
| AT-28 | Conversion proof tamper / package | Ed25519 proof | `ConversionProofServiceTest` | `PROOF_INVALID` | key custody deployment scoped |
| AT-29 | Audit record modification / log | hash chain/signature | `AuditHashChainTest` | chain invalid | external anchor deployment scoped |
| AT-30 | Audit proof wrong signer / root | Ed25519 public key | `AuditProofServiceTest` | proof invalid | public-key publication required |
| AT-31 | Nonce reuse / AEAD key | nonce registry | `AesGcmNonceManagerTest` | rejected | multi-instance DB wiring required |
| AT-32 | Idempotency body collision / write API | body-hash record | `ApiIntegrationTest` | `IDEMPOTENCY_CONFLICT` | multi-instance storage required |
| AT-33 | Threshold short quorum / rekey | t-of-n combine | `ThresholdReEncryptionServiceTest` | `THRESHOLD_NOT_REACHED` | experimental construction |
| AT-34 | Threshold forged share / rekey | share signature | `ThresholdReEncryptionServiceTest` | `THRESHOLD_SHARE_INVALID` | colluding quorum remains trusted |
| AT-35 | ECC proxy-recipient collusion / owner key | baseline labeling | `EccCollusionBoundaryTest` | risk demonstrated | prohibited in production |
