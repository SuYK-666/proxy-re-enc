# Re-encryption Key Scope

`ScopedReEncryptionKey` 绑定以下字段：

- `grantId`、`dataId`、`recipientId`
- `ownerKeyVersion`、`policyHash`
- `expiresAt`、`maxUsage`

Proxy 在转换 capsule 之前原子消费 scope；任一字段不一致、已过期或达到上限
均拒绝。底层 baseline rekey 只有在 scope 检查通过后才会交给算法实现。
`ScopedReEncryptionKeyTest` 验证跨作用域拒绝和限次行为。
