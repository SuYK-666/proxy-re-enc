# Key Lifecycle

领域模型保存 key id、fingerprint、purpose、version 与状态；production 用户注册以 `registerPublicOnlyUser` 落库，repository 内 private key 为 `null`。production 不提供服务端 key rotation 或 demo recipient-share 路径。Owner-side rotation 提升 content key version，并使旧活动授权失效。

Demo 内的 `DemoPrivateKeyStore` 只用于在同一进程中验证接收方解密正确性，不属于 production custody 模型。生产部署应由客户端或 KMS/HSM 保管私钥和托管签名材料。
