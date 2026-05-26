# Repository Design

当前系统保留两类实现：

| 实现 | 用途 | 边界 |
| --- | --- | --- |
| `InMemory*Repository` | demo、单元/API 测试 | 进程退出后状态不恢复 |
| `JdbcAuditRepository` + `schema.sql` | 审计链持久化与重启恢复证据 | 生产部署需提供外部不可篡改 anchor |
| `JdbcGovernanceRepository` | data/grant/package 治理元数据持久化、撤销事务和限次 CAS | 密文内容仍由对象存储保存，HTTP runtime 默认使用内存适配器 |

`schema.sql` 定义 users/data/grants/packages、nonce 唯一键、token revocation 以及与 `JdbcAuditRepository` 一致的 audit 字段。`JdbcGovernanceRepositoryTest` 使用第二个 repository 实例模拟重启恢复，并在 100 个并发请求下验证 `maxAccess=3` 仅成功消费 3 次；`JdbcAuditRepositoryTest` 验证持久化 hash-chain 连续。

本仓库提供的 JDBC 治理 adapter 可作为多实例事务接入点；当前无依赖 HTTP 演示服务器仍默认选择内存 repository。部署时必须将 API 装配到 JDBC adapter，并把 ciphertext 对象存储、迁移工具与备份恢复策略纳入运行配置。
