# Revocation And Rotation

`KeyLifecycleService` 以客户端密文边界编排撤销：

| Mode | Effect |
| --- | --- |
| `SOFT_REVOKE` | 撤销 grant，并阻断该 grant 的新转换和包下载 |
| `HARD_REVOKE` | soft 效果，加上 owner 提交的新密文/content key version |
| `EMERGENCY_REVOKE` | 撤销对象的全部活动 grant，再接受 owner rotation |

服务端不会为 rotation 解密正文或生成 DEK。hard/emergency 后旧 package
因状态或旧 `contentKeyVersion` 被拒绝；若要让未撤销 recipient 继续访问，
owner 必须在新版本上签发新 grant/package。证据为
`KeyLifecycleServiceTest` 与 [`reports/raw/e06-revocation-results.json`](reports/raw/e06-revocation-results.json)。
