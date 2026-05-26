# Database Migration

The executable bootstrap DDL is [../src/main/resources/db/schema.sql](../src/main/resources/db/schema.sql);
`JdbcSchemaInitializer` applies it to embedded H2 for adapter integration tests.

Security-state tables include `data_objects`, `grants`, `packages`, `aes_gcm_nonces`,
`key_versions`, `proxy_nodes`, `idempotency_records`, `rewrap_jobs`, `token_revocations`,
`audit_events` and `audit_public_keys`. Compound tenant keys and nonce uniqueness are
defined in DDL.

`JdbcGovernanceRepositoryTest` verifies restart-style reconstruction, atomic access
limits, revoke/package invalidation, and tenant-scoped mutation isolation.
`JdbcAuditRepositoryTest` verifies recovered audit-chain continuity.

The default lightweight HTTP runtime remains in-memory; production deployment must inject
the JDBC adapters (and object storage/KMS integrations) before claiming durable
multi-instance operation. A future Flyway/Liquibase migration history is required once
schema upgrades, rather than initial bootstrap, are shipped.
