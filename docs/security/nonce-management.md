# Nonce Management

AES-256-GCM 要求同一 key 下 nonce 不复用。`AesGcmNonceManager` 将
`(key fingerprint, nonce)` 保存至 registry，数据库 schema 同时定义
`aes_gcm_nonces` 主键唯一约束。

单进程文件 adapter 在启动或模拟重启后一次加载 tombstone 集合，后续预留
仅作集合唯一判断和 append，不会为每个流式 chunk 重读完整 registry。
`AesGcmNonceManagerTest` 覆盖重启、并发同 nonce 与 2,000 次 append 批次。

测试与实验脚本通过 `-Drekeyshare.nonce.registry=target/experiment/...` 使用
临时 registry，防止实验执行覆盖版本控制下的样例。真实多实例部署应使用
事务数据库唯一索引，而不是共享文本文件。
