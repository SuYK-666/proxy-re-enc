# Architecture

本文件是验收入口，详细模块图、数据流、信任边界和状态机分别见：

- [系统架构](architecture/system-architecture.md)
- [状态机](architecture/state-machines.md)
- [安全边界](security/security-boundary.md)
- [存储模型](storage/schema.md)

正式边界为客户端产生明文和 DEK，服务端仅托管密文与可验证元数据。
`PRODUCTION` 不发布 RSA/ECC baseline 的 grant/re-encrypt 路由；
`SECURE_ENVELOPE_V1` 是默认正式 provider。代理转换演示以及阈值转换目前
分别属于 `DEMO_*` 与 `THRESHOLD_EXPERIMENTAL` profile。
