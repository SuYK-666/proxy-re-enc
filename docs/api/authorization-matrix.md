# Authorization Matrix

| Resource/action | Actor | Control | Negative evidence |
| --- | --- | --- | --- |
| object metadata/read | owner or active recipient | `ObjectAuthorizationService` | `UnauthorizedAccessTest` |
| grant/create | owner, demo baseline only | ownership + profile route guard | `ApiIntegrationTest` |
| grant/revoke | owner | owner check + package invalidation | `ReKeyShareLifecycleTest` |
| package/download | recipient | grant state, policy, context, proof | `PolicyActionAuthorizationTest` |
| proxy transform | active assigned proxy, demo only | role/node/quota/profile | `ProxyNodeServiceTest` |
| audit/export | admin | token role | `ApiIntegrationTest` |

生产 OpenAPI 不提供 baseline transform；正式 envelope/代理部署需要将身份
tenant 条件持久化装配到 repository 查询中。
