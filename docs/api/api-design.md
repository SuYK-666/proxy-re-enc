# API Design

正式 API 主线：

| Endpoint | 主体 | 行为 |
| --- | --- | --- |
| `POST /api/data/upload-encrypted` | owner | 接收客户端 ciphertext/capsule |
| `POST /api/grants` | owner | demo baseline grant；production 需要客户端 rekey 集成 |
| `POST /api/proxy/re-encrypt` | active proxy | 校验 scope/quota/scheme 后转换 capsule |
| `GET /api/shared-packages/{id}` | recipient | 返回并验证 `SharedPackageV2` |
| `POST /api/grants/{id}/revoke` | owner | 撤销并失效活动 package |
| `GET /api/audit/proof` | admin | 导出审计 proof |

`PRODUCTION` 不公开明文上传、明文解密、服务端私钥轮换或 demo recipient-share；完整 OpenAPI catalog 由服务的 `/openapi.json` 返回。错误格式见 [error-model.md](error-model.md)，请求体限制、幂等与限流见 [security-controls.md](security-controls.md)。
