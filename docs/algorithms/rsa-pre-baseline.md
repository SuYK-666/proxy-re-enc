# RSA PRE Baseline

本实现基于公共模数与指数转换关系，用于解释 capsule 的代理转换流程和与 ECC baseline 的性能比较。它不是通用、经过审查的生产 PRE 协议。

## 边界

- 参数标记为 `RSA-PRE-demo-common-modulus-*`，descriptor 为 `baselineOnly=true`。
- 公共模数假设会引入密钥关联风险，不能成为 production 唯一路径。
- capsule 通过 AES-256-GCM 包装 DEK，并由 `CapsuleContext` 的 AAD 绑定对象/策略/版本。
- `ScopedReEncryptionKey` 限制 grant、data、recipient、key version、policy、过期时间及次数。

生产替代路线见 [secure-envelope-provider.md](secure-envelope-provider.md)；如需要真正代理语义，应接入经过公开审查的 PRE 实现。
