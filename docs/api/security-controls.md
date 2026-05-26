# API Security Controls

## Request Boundary

- `PRODUCTION` profile 只接受 `SECURE_ENVELOPE` 客户端密文路径并拒绝 RSA/ECC baseline；不注册 demo plaintext upload/decrypt 和服务端私钥轮换路径。
- 所有 `POST` 请求必须使用 `application/json` 或 `application/x-www-form-urlencoded`；
	畸形 JSON、不支持的 media type 和超过 1 MiB 的 body 返回 4xx。
- 安全失败响应包含 `errorCode`、`traceId`、`eventId` 与 `timestamp`，不输出异常栈或密钥材料。

## Replay And Rate Limits

- `IdempotencyService` 在 HTTP 写路由绑定 actor/action/resource/body-hash：
  同键同请求返回首次响应，同键异请求返回 `IDEMPOTENCY_CONFLICT`。多实例部署
  必须使用 `idempotency_records` 表，以保持节点间一致回放。
- 认证或授权失败按远端地址累积，超过窗口阈值返回 `RATE_LIMITED`。
- 下载计数在单实例 API 中受同步临界区保护；JDBC 部署 adapter 使用原子条件更新保证 `access_count < max_access_count`。

## Evidence

`ApiIntegrationTest` 覆盖 production 明文边界、错误追踪、并发下载、幂等重放、畸形 JSON 与不支持的 content type。`E11` 原始数据见 `../reports/raw/e11-api-robustness-results.json`。
