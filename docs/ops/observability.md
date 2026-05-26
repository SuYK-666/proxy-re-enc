# Observability

API 错误通过 `traceId`、`eventId` 与 UTC `timestamp` 关联请求和审计调查；审计 proof 提供链完整性验证；experiment summary 提供运行环境和耗时结果。

本原型没有内嵌外部 metrics exporter。正式部署可从 API 延迟、proxy transform 时间、拒绝错误码与 package 验证失败数导出 Prometheus/OpenTelemetry 指标，并确保 label 不包含明文或密钥材料。
