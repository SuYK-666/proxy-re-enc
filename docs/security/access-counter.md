# Access Counter Semantics

授权的 `maxAccessCount` 是成功消费上限，而不是请求尝试次数。服务拒绝过期、撤销或超过限额的访问，并且不能在并发竞争中超发。

本地 HTTP 演示适配在单 JVM 内以同步临界区更新访问次数；`JdbcGovernanceRepository.consumeGrantAccess` 为持久化/多线程证据路径，执行带条件的原子更新，仅当 grant 为 `ACTIVE` 且当前计数小于最大计数时成功。

验证证据：

- `ApiIntegrationTest.concurrentDownloadsCannotExceedAccessLimit`：100 个并发下载下验证 `maxAccess=1/3/10`。
- `JdbcGovernanceRepositoryTest`：重启后的 JDBC 元数据在 100 个竞争请求下验证 `maxAccess=3` 不超发。
- `docs/reports/raw/e10-persistence-recovery-results.json`：记录持久化恢复与原子消费数据。
