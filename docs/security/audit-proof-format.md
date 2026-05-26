# Audit Proof Format

审计事件以 `previousHash -> eventHash` 形成 hash-chain；`AuditProofService` 导出：

```json
{"generatedAt":"...","eventCount":2,"chainRoot":"...","merkleRoot":"...","signature":"..."}
```

当前 signature 是用于原型验证的服务内 anchor；外部生产证据应将 checkpoint 提交到不可篡改存储或外部签名/时间戳服务。删除、重排与字段修改由 `AuditHashChainTest`、`AuditProofServiceTest` 及已有 raw 报告覆盖。
