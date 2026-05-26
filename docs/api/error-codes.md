# Error Codes

The wire response shape and HTTP classification are specified in
[error-model.md](error-model.md). Security-stable codes include:

| Code | Condition |
| --- | --- |
| `AUTHN_FAILED` / `ACCESS_DENIED` | Missing identity or unauthorized object access |
| `GRANT_REVOKED` / `GRANT_ROTATED` | Stale grant/package use |
| `CRYPTO_PROFILE_NOT_ALLOWED` | Baseline suite requested in production |
| `CRYPTO_CONTEXT_MISMATCH` | Canonical AAD mismatch |
| `PROOF_INVALID` | Conversion proof missing, altered or untrusted |
| `NONCE_CONFLICT` | AES-GCM nonce reuse attempt |
| `IDEMPOTENCY_CONFLICT` | Same idempotency key, different request hash |
| `INVALID_STATE_TRANSITION` | Terminal or illegal lifecycle transition |

The API returns traceable, sanitized errors; authorization failures do not reveal whether
the target identifier exists.
