# 状态机

`StateTransitionGuard` 对关键聚合的合法迁移进行统一拒绝；非法迁移返回 `INVALID_STATE_TRANSITION`。

| 聚合 | 合法状态迁移 |
| --- | --- |
| Data | `ACTIVE -> ROTATING/REVOKED/DELETED`, `ROTATING -> ACTIVE/REVOKED` |
| Grant | `CREATED -> ACTIVE`, `ACTIVE -> EXPIRED/REVOKED/ROTATED` |
| Package | `ACTIVE -> EXPIRED/INVALIDATED/ROTATED` |
| Proxy | `ACTIVE -> DISABLED/REVOKED`, `DISABLED -> ACTIVE/REVOKED` |
| Key | `ACTIVE -> ROTATED/REVOKED`, `ROTATED -> REVOKED` |

撤销实现只失效仍为 `ACTIVE` 的 package；轮换不把已经 `REVOKED` 的 grant 覆写为 `ROTATED`。该规则防止终态被后续任务意外改写。
