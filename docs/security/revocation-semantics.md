# Revocation Semantics

| 操作 | 效果 | 不承诺的效果 |
| --- | --- | --- |
| 逻辑撤销 | grant 从 `ACTIVE` 到 `REVOKED`，后续转换/下载拒绝 | 收回既有明文 |
| 包失效 | 已签发且仍活动的 package 到 `INVALIDATED` | 删除接收方下载副本 |
| Owner-side rotation | 新 ciphertext/DEK/keyVersion；旧活动 grant/package 进入 `ROTATED` | 自动重授权所有用户 |

实现中的 `StateTransitionGuard` 防止终态覆盖：已撤销 grant 不会在后续 rotation 中变回另一个可误读状态。`ReKeyShareLifecycleTest` 和 API 撤销验证覆盖旧包不可继续使用。
