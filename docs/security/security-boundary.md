# 安全边界

## 强制边界

- `PRODUCTION` profile 不注册 demo 明文上传或 demo 解密路由。
- `PRODUCTION` 的用户注册只保存 public key material；服务端 key rotation 与 recipient-share-demo 被禁用。
- `/api/shared-packages/{id}` 仅返回 ciphertext、nonce、AAD、capsule 与验证元数据，不返回 plaintext。
- 服务端正式模型和快照不应持久化文件明文、DEK 明文或用户 private key。
- package V2 在下载路径生成并验证 manifest；ciphertext、AAD、capsule、policy/context 的修改必须拒绝。
- 错误响应包含 `traceId`/`eventId`/`timestamp`，内部异常不返回堆栈或具体内部原因。

## 有限边界

- Demo profile 中的明文路由仅用于测试/演示。
- 当前正式 API 的完整 PRE rekey 需要后续接入客户端/KMS 提交材料；不会以服务端私钥代替该集成。
- 内存 repository 与 demo token 不是企业认证/持久化方案。
- 已由合法接收方离线保存的明文无法通过撤销技术性收回。
- RSA/ECC baseline 只用于实验，不构成生产密码承诺。

验证入口：`ApiIntegrationTest.productionProfileDoesNotExposeDemoPlaintextRoutes`、`SecurityBoundaryServiceTest`、`PackageVerifierTest` 与 `scripts/check-security-boundary.*`。
