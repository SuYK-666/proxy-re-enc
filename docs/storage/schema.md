# Storage Schema

关键安全约束：

- `aes_gcm_nonces` 以 `(tenant_id, key_id, nonce)` 为主键，并保留
  `(key_fingerprint, nonce)` 唯一约束，支持 nonce tombstone/重启防复用。
- `grants` 与 `packages` 记录状态和 `content_key_version`，供轮换/撤销判断；`max_access_count` 与条件更新支持原子限次。
- `packages` 可保存 `conversion_proof_digest` 与 proof signer key id；下载路径在计数前校验 proof。
- `key_versions`、`proxy_nodes`、`idempotency_records` 与 `rewrap_jobs`
  为生产 repository 装配预留持久化约束。
- `audit_events` 持久化 event hash、previous hash、trace/request metadata 与错误字段，支持重启后验证。
- `audit_public_keys` 保存 Ed25519 verification key 的轮换元数据，供外部 verifier 配置可信根。
- `data_objects` 仅记录 ciphertext hash 与 storage path，不设计 plaintext/DEK/private key 列。

完整 DDL 位于 `src/main/resources/db/schema.sql`。

`JdbcGovernanceRepository` 当前将 data/grant/package 治理元数据写入该 schema；
新增表是下一步 HTTP runtime durable adapter 的约束面，不能误述为默认内存
服务器已持久化所有状态。恢复与并发证据见
`../reports/raw/e10-persistence-recovery-results.json`。
