# Multi-Tenant Isolation

The deployable persistence boundary uses `tenant_id` in compound identifiers and every
`JdbcGovernanceRepository` query/update. Two tenants may hold identical object, grant and
package identifiers without revoke or counter mutations crossing the tenant boundary;
`JdbcGovernanceRepositoryTest` verifies this case.

Cryptographic isolation is independent of storage filtering: `tenantId` is one of the 12
canonical AAD fields in `CapsuleContext`, and `CryptoProviderTest` verifies that replacing
it prevents DEK recovery.

The lightweight HTTP demo is not wired to tenant-scoped JDBC storage, and the current
generic audit-event model does not expose a first-class tenant query. Production
multi-tenant and per-tenant audit claims therefore require durable runtime wiring plus a
tenant-bearing audit schema/API extension.
