# Streaming AEAD

`AesGcmChunkedEncryptor` 和 `AesGcmChunkedDecryptor` 使用独立 nonce 与
`chunk index + base AAD` 保护每个 chunk。
`MerkleChunkTree` 将各 chunk ciphertext hash 汇总为 root。

- 默认实验 chunk size：128 KiB；服务调用可显式配置，单片独立认证。
- 解密前验证 Merkle root，并逐块检查 ciphertext hash。
- 单个 chunk 被替换时，拒绝信息可定位 chunk index。
- E03 runner 在受控 `-Xmx12m` JVM 中对 1 MiB、10 MiB 和 100 MiB 各采样
  30 次，记录观测 heap peak delta 与 128 KiB 配置工作缓冲区，并验证
  chunk 修改、删除、重排以及对象 AAD 替换均被拒绝。测量采用 JVM 自然 GC
  行为；观测 heap 值包含 JVM/JIT/GC 噪声，不等同于算法缓冲区上界。
