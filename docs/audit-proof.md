# Audit And Conversion Proof

审计事件以 `previousHash`/`eventHash` 组成 hash chain。`AuditProofService`
计算 Merkle root，并以 Ed25519 私钥签名 checkpoint；导出包含
`signatureAlgorithm`、encoded public key 与 signature，支持离线 verifier
固定可信公钥后验证。

每个代理转换包另有 `ConversionProof`，绑定：

- `algorithmSuite`、object digest、grant digest、capsule digest、package digest。
- `proxyId`、签发时间、随机 nonce、Ed25519 signer key。

下载前 `PackageVerifier.verifyFormalPackage` 以当前 grant 和运行态可信代理
公钥校验 proof；失败产生审计事件，且不消耗下载额度。证据见
`AuditProofServiceTest` 与 `ConversionProofServiceTest`。
