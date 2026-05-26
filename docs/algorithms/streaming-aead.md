# Streaming AEAD

`AesGcmChunkedEncryptor` 和 `AesGcmChunkedDecryptor` 使用独立 nonce 与
`chunk index + base AAD` 保护每个 chunk。
`MerkleChunkTree` 将各 chunk ciphertext hash 汇总为 root。

- 默认 chunk size：1 MiB。
- 解密前验证 Merkle root，并逐块检查 ciphertext hash。
- 单个 chunk 被替换时，拒绝信息可定位 chunk index。
- E03 runner 验证 1 MiB、10 MiB 和 100 MiB 文件，明文工作缓冲区受 chunk size 约束。
