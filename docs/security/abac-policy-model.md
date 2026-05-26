# ABAC Policy Model

`security/policy` 将策略拆为 `PolicyExpression`、`PolicyRequest` 和 `PolicyDecision`，判定结果包含稳定 `policyHash` 与 `reasonCode`。

| 维度 | 当前支持 |
| --- | --- |
| Subject | role、tenantId、subjectId |
| Resource | dataId、classification |
| Action | download、preview 等允许动作集合 |
| Context | purpose、notBefore、expiresAt、maxAccessCount、proxyActive |

拒绝原因包括 `TENANT_DENIED`、`ROLE_DENIED`、`PURPOSE_DENIED`、`GRANT_EXPIRED`、`ACCESS_LIMIT_EXCEEDED` 与 `PROXY_INACTIVE`。`PolicyEvaluatorTest` 执行 10 条许可和 10 条拒绝 case；现有 API grant 继续保留 `AccessPolicy` 兼容结构及 `policyHash` 审计绑定，后续可将 JSON policy 解析直接映射至本引擎。
