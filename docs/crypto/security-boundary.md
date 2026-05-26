# Cryptographic Security Boundary

## Enforced

- `CryptoProfile.productionDefault()` 为 `STANDARD_ENVELOPE`。
- 正式 OpenAPI 不公开 baseline grant、recipient-share 或 proxy transform 路由。
- 正式下载需要 `ConversionProof`，proof 绑定对象、授权、胶囊、package、
  proxy、时效和 nonce，并以可信代理 Ed25519 公钥验证。
- audit root/checkpoint 以 Ed25519 签名，不再依赖共享 secret。

## Not Promised

- RSA common-modulus 与实验 ECC PRE 不是生产密码协议。
- threshold share proof 降低单代理持有完整 rekey 的风险，但不消除达到阈值后的合谋。
- 撤销阻断系统内后续访问，不能追回接收方此前离线保存的明文。
- KMS/HSM、企业身份、WORM audit anchor 和多实例 durable runtime 需要部署集成。
