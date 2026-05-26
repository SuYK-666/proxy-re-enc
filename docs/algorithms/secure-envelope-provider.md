# Secure Envelope Provider

`SECURE_ENVELOPE_V1` 使用 JCA `secp256r1` ECDH、HKDF-SHA256 和 AES-256-GCM 包装 DEK：

1. 为每个 capsule 生成 ephemeral P-256 key pair。
2. 使用 ephemeral private key 与 recipient public key 派生共享秘密。
3. 使用上下文 AAD 派生 KEK，并由 AES-GCM 包装 DEK。
4. recipient 使用自己的 private key 与 capsule 中 ephemeral public key 解封装。

该 provider 选择成熟 JCA 原语并绑定 `CapsuleContext`；修改 policy/data/keyVersion/AAD 会导致拒绝。它是直接接收方 envelope，不执行代理转换，因此不冒充 PRE。
