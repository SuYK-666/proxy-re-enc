# Container Hardening

| 控制 | 实现 |
| --- | --- |
| Multi-stage | JDK build stage，只复制 compiled classes 至运行镜像 |
| 最小运行时 | `eclipse-temurin:17-jre` |
| 非 root | `USER rekeyshare:rekeyshare` |
| Healthcheck | `HealthCheckApplication` 请求本机状态端点 |
| 只读根文件系统 | Compose `read_only: true`；仅挂载 storage/reports 与 `/tmp` |
| 权限收敛 | `no-new-privileges:true` |
| 资源边界 | Compose CPU/内存 limit |

容器默认设置 `REKEYSHARE_PROFILE=production`，不会开放 demo 明文接口。
