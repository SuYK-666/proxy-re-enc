# API Security Controls

## Request Boundary

- `PRODUCTION` profile 不注册 demo plaintext upload/decrypt 和服务端私钥轮换路径。
- 所有 `POST` 请求必须使用 `application/json` 或 `application/x-www-form-urlencoded`；
	畸形 JSON、不支持的 media type 和超过 1 MiB 的 body 返回 4xx。
- 安全失败响应包含 `errorCode`、`traceId`、`eventId` 与 `timestamp`，不输出异常栈或密钥材料。

## Replay And Rate Limits

- 可变更请求接受 `Idempotency-Key`；同一路径同一 key 的第二次提交被拒绝，不产生第二份有效结果。
- 认证或授权失败按远端地址累积，超过窗口阈值返回 `RATE_LIMITED`。
- 下载计数在单实例 API 中受同步临界区保护；JDBC 部署 adapter 使用原子条件更新保证 `access_count < max_access_count`。

## Evidence

`ApiIntegrationTest` 覆盖 production 明文边界、错误追踪、并发下载、幂等重放、畸形 JSON 与不支持的 content type。`E11` 原始数据见 `../reports/raw/e11-api-robustness-results.json`。
