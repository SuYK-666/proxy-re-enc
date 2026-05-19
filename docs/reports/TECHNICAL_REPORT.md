# ReKeyShare 技术状态报告

## 总体状态

ReKeyShare 当前已经从单纯 PRE 算法 demo 扩展为一个面向半可信云存储场景的数据安全共享管理系统原型。系统主线是：

1. 使用 AES-256-GCM 加密正文。
2. 使用 RSA/ECC 教学型 PRE 封装和转换 DEK 胶囊。
3. 使用 `ShareGrant` 和 `AccessPolicy` 管理授权生命周期。
4. 使用对象级授权阻止 dataId、grantId、packageId 猜测攻击。
5. 使用 revoke 和 contentKeyVersion 实现软撤销与内容密钥版本轮换。
6. 使用哈希链审计和 benchmark 报告支撑可核查演示。

## 已落地硬化项

- 正式共享包接口 `GET /api/shared-packages/{packageId}` 只返回密文、nonce、AAD、grant AAD、re-encrypted capsule 和策略上下文元数据，不返回明文。
- 明文验证接口隔离在 `/api/demo/shared-packages/{packageId}/decrypt`，用于课程演示和测试正确性。
- API 使用 HMAC demo bearer token，默认禁用 `X-Actor-Id` legacy shortcut。
- API 支持 `/api/v1/...` 路径别名。
- API 错误响应统一包含 `success:false`、`code`、`message`、`requestId`。
- `SchemeRegistry` 支持 RSA/ECC 双算法分发，API 默认 RSA 参数为 3072-bit demo common modulus。
- ECC grant 必须使用 recipient share；服务层已删除通过 recipient private key 生成 share 的 fallback。
- legacy `AuthorizationService.authorize()` 已禁用，正式主线统一为 `createGrant()` + `ProxyReEncryptionService.reEncrypt()`。
- `PreScheme` 已支持 `CapsuleContext` 参数，RSA/ECC KDF label 使用 `ReKeyShare|<ALG>|DEK-WRAP|v1` 域隔离。
- `ShareGrant` 拆分 re-encrypt、download、decrypt、preview 计数，proxy 重加密不再消耗 recipient access count。
- `GrantAction` 区分 `PROXY_REENCRYPT`、`PREVIEW`、`DOWNLOAD`、`RESHARE`、`DECRYPT_DEMO`、`VIEW_AUDIT`。
- `ObjectAuthorizationService` 对 data、grant、package、proxy、revoke、download、decrypt、preview 执行动作级授权。
- `AesGcmNonceManager` 检测同一 AES-GCM key 下 nonce 复用。
- `P256Curve.decode()` 校验 uncompressed point 格式、曲线方程和规范域元素坐标。
- 用户 key rotation 通过 `UserService.rotateUserKey()` 生成真实新 keypair，再由 `KeyManagementService.rotateKey()` 轮换 KeyVersion。
- `AuditService.verifyChain()` 独立重算哈希链，不依赖具体 repository 的 fallback。
- 新增 `JdbcAuditRepository`，提供基于 JDBC/H2 的 append-only 审计事件持久化基础。
- JSON body 解析已抽出 `JsonFields`，支持字符串转义、Unicode、嵌套对象/数组的顶层解析。
- OpenAPI 输出已包含核心请求/响应 schema。
- benchmark summary 增加 p50、p95、p99、stddev、throughput 指标。
- Dockerfile、docker-compose、GitHub Actions CI、威胁模型、安全边界、API 设计和攻击矩阵文档均已存在。

## 当前边界

- RSA-PRE 和 ECC-PRE 仍是教学型原型，不是生产级密码协议。
- `/api/demo/**` 属于 demo-only，生产 profile 应禁用。
- 默认 API 存储仍是内存仓库加 JSON snapshot/export manifest；JDBC 当前优先覆盖审计链持久化。
- JSON 解析器是项目内轻量实现；生产化建议替换为 Jackson 并引入 DTO validation。
- `rotateContentKey(...)` 是服务端明文 demo helper；安全主线应使用 `acceptOwnerSideRotation(...)` 接受 owner 客户端预先加密的新版本。

## 验证结果

```text
javac --release 17 main compile: PASS
javac --release 17 test compile: PASS
TestSuiteRunner: Tests run: 59, Failures: 0
```

## 建议下一步

- 将 data/grant/package/user repository 扩展为完整 JDBC/H2 或 SQLite 实现。
- 用 Jackson + DTO + Bean Validation 替换轻量 JSON parser。
- 将 `/api/demo/**`、测试小参数 RSA 1024-bit 和 demo private-key fixture 放入明确 profile。
- 将教学型 PRE 替换为经过审查的 PRE、Threshold PRE、Umbral-style PRE 或 HPKE 方案。
- 引入更完整的 OpenAPI schema、分页查询、审计过滤和持久化 root anchor。
