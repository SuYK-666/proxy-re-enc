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

`code`/`requestId` 为向后兼容字段。无 token 返回 401；畸形输入和 package
完整性错误返回 400；授权/策略/代理拒绝返回 403；限流返回 429。
未处理异常只返回通用 `internal server error`，不泄露内部细节。

新增安全错误码：

| Code | Meaning |
| --- | --- |
| `CRYPTO_PROFILE_NOT_ALLOWED` | profile 禁止 baseline/不匹配 suite |
| `CRYPTO_CONTEXT_MISMATCH` | 上传 AAD 与 canonical envelope context 不匹配 |
| `PROOF_INVALID` | conversion proof 缺失、篡改、过期或 signer 不可信 |
| `THRESHOLD_NOT_REACHED` | 合法 share 数不足阈值 |
| `THRESHOLD_SHARE_INVALID` | share proof 或代理签名无效 |
| `IDEMPOTENCY_CONFLICT` | 相同 key 被用于不同请求体 |
