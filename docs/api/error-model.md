# API Error Model

所有错误响应采用统一追踪字段：

```json
{
  "success": false,
  "errorCode": "GRANT_REVOKED",
  "code": "GRANT_REVOKED",
  "message": "grant revoked",
  "traceId": "req-...",
  "requestId": "req-...",
  "eventId": "err-...",
  "timestamp": "2026-05-26T00:00:00Z"
}
```

`code`/`requestId` 为向后兼容字段。无 token 返回 401；畸形输入和 package 完整性错误返回 400；授权/策略/代理拒绝返回 403；限流返回 429。未处理异常只返回通用 `internal server error`，不泄露内部细节。
