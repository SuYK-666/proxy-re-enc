# Data Model

DDL 源文件为 [`../src/main/resources/db/schema.sql`](../src/main/resources/db/schema.sql)。

| Aggregate/table | Security fields |
| --- | --- |
| `data_objects` | tenant, owner, ciphertext hash, content key version |
| `grants` | recipient, status, policy hash, counters, key version |
| `packages` | status, key version, conversion proof digest/key id |
| `aes_gcm_nonces` | tenant/key/nonce unique tombstone |
| `key_versions` | algorithm suite, version, retirement reason |
| `proxy_nodes` | status, signing public key, quota |
| `idempotency_records` | actor/action/resource/key/body hash/expiry |
| `audit_events`, `audit_public_keys` | hash chain and signature trust roots |

默认 HTTP demo 仍使用内存 repository；JDBC 迁移设计和部分恢复证据存在，
生产部署必须完成 durable runtime wiring 后才可声称全部状态持久化。
