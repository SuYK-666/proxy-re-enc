# Context Binding

`SECURE_ENVELOPE_V1` 使用 `AadBuilder` 构造长度前缀编码的 canonical AAD。
下列字段全部参与 DEK envelope 的 AES-GCM 认证：

| Field | Purpose |
| --- | --- |
| `tenantId` | 隔离租户范围 |
| `dataId` | 绑定密文对象 |
| `ownerId` | 绑定数据所有者 |
| `recipientId` | 绑定获授权接收者 |
| `algorithm` | 防止算法类型替换 |
| `algorithmSuite` | 防止 suite/version 降级 |
| `ownerKeyId` | 绑定 owner key 身份 |
| `contentKeyVersion` | 防止旧 DEK envelope 重放 |
| `policyHash` | 绑定授权条件 |
| `grantId` | 绑定授权实例 |
| `proofIssuerId` | 绑定转换证明签发方 |
| `operation` | 防止 upload/download/re-encrypt 场景混用 |

`CryptoProviderTest` 针对以上 12 个字段逐项替换并要求解封失败；
`DataSecurityService.uploadEncrypted` 还会在写入前拒绝不匹配 canonical AAD
的客户端密文。`ConversionProof` 另外绑定 package 和 capsule digest，因此
转换包下载同时受 AAD 与 proof 两层验证。
