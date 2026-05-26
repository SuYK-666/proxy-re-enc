# Storage Schema

关键安全约束：

- `aes_gcm_nonces` 以 `(key_fingerprint, nonce)` 为主键，禁止 AEAD nonce 重复。
- `grants` 与 `packages` 记录状态和 `content_key_version`，供轮换/撤销判断；`max_access_count` 与条件更新支持原子限次。
- `audit_events` 持久化 event hash、previous hash、trace/request metadata 与错误字段，支持重启后验证。
- `data_objects` 仅记录 ciphertext hash 与 storage path，不设计 plaintext/DEK/private key 列。

完整 DDL 位于 `src/main/resources/db/schema.sql`。

`JdbcGovernanceRepository` 将 data/grant/package 治理元数据写入该 schema；其恢复与并发证据见 `../reports/raw/e10-persistence-recovery-results.json`。
