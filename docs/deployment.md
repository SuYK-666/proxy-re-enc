# Deployment And Verification

## Profiles

| Profile | Allowed use |
| --- | --- |
| `STANDARD_ENVELOPE` | production default provider; `SECURE_ENVELOPE_V1` only |
| `DEMO_RSA`, `DEMO_ECC` | local teaching/benchmark; not exposed in production OpenAPI |
| `THRESHOLD_EXPERIMENTAL` | signed-share experiment only |

HTTP demo switch remains `-Drekeyshare.profile=demo`; without it the server omits
plaintext, baseline grant and baseline proxy transform routes.

## Production Integrations

- Persist `schema.sql` tables in a managed database and wire durable repositories.
- Provision Ed25519 audit/proxy signing private keys in KMS/HSM and distribute pinned public keys.
- Replace demo bearer tokens with OIDC/mTLS identity carrying tenant scope.
- Store ciphertext in managed object storage and anchor audit roots to append-only storage.

These integrations are requirements for a production deployment, not claims about the
default in-memory executable.

## Verification

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify-all.ps1
```

The command executes `mvn verify` (tests, coverage, SpotBugs and SBOM), security
gates, reproducible experiments, link/performance checks and writes
`docs/reports/final-verification.md`.

For offline component-level JSON verification commands, see
[cli-verification.md](cli-verification.md).
