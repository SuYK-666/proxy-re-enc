# Envelope Scheme

`SecureEnvelopeProvider` 实现 `SECURE_ENVELOPE_V1`：

1. sender 生成临时 P-256 ECDH 密钥。
2. shared secret 经 HKDF-SHA256 派生 AES-256-GCM KEK。
3. KEK 仅封装 DEK；文件密文不因新增 recipient 被重复加密。
4. capsule 携带临时公钥、wrapped key、nonce、suite/version 与 context hash。

AAD 规范绑定 `tenantId`、对象、owner、recipient、grant、policy、content-key
version、algorithm type/suite、owner key、proof issuer 与 operation。
任一字段变化都会导致 GCM 验证失败；12 个字段替换负例见 `CryptoProviderTest`，
字段编码见 [context-binding.md](context-binding.md)，原始正确性数据见
[`../reports/raw/e01-secure-envelope-correctness.csv`](../reports/raw/e01-secure-envelope-correctness.csv)。
