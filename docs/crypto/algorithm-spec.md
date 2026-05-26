# Algorithm Specification

| Suite | Profile | Use | Security statement |
| --- | --- | --- | --- |
| `RSA_PRE_BASELINE` | `DEMO_RSA` | 教学和性能对照 | 不承诺 CCA 或生产 PRE 安全 |
| `ECC_PRE_BASELINE` | `DEMO_ECC` | 教学和性能对照 | 不抗代理与接收方合谋 |
| `SECURE_ENVELOPE_V1` | `STANDARD_ENVELOPE` | 直接接收方 key envelope | P-256 ECDH, HKDF-SHA256, AES-256-GCM |
| threshold share proof | `THRESHOLD_EXPERIMENTAL` | 分片转换实验 | 不声称完全抗合谋 |

`CryptoProfileGuard` 强制 provider/profile 配对；正式默认只能选择
`SECURE_ENVELOPE_V1`。数据正文使用 AEAD，授权变化只应重封装 DEK，
不得由服务端解密正文再重加密。

上下文认证字段由 `CapsuleContext`/grant context 覆盖 `tenantId`、object、
owner、recipient、`grantId`、algorithm suite、owner key、content-key version、
policy hash、proof issuer 与 operation。正式上传只接受与该 canonical context 匹配的
AAD；持久化多租户身份来源仍属于部署集成边界。
