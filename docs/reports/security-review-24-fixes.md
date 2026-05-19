# Security Review 24-Issue Fix Log

Date: 2026-05-19

| Issue | Resolution |
|---|---|
| 1 | RSA/ECC PRE demoted to baseline/demo. Formal direction documented as client-side AEAD plus reviewed HPKE/PRE replacement. |
| 2 | Common-modulus RSA kept only as baseline; production/demo profile boundary prevents presenting it as formal security guarantee. |
| 3 | `RsaPrivateKeyMaterial` no longer carries `phi`; `phi` is package-private inside RSA baseline parameters. |
| 4 | ECC recipient share changed from raw inverse scalar to session/challenge/expiry-bound masked share. |
| 5 | Demo decrypt route only exists in demo profile; production OpenAPI does not expose it. |
| 6 | `plaintextHashForDemo`, plaintext-derived hash fields, and plaintext-taking package factories removed from core models. |
| 7 | AES-GCM nonce registry now persists `(key fingerprint, nonce)` reservations under `storage/security/aes-gcm-nonces.txt`. |
| 8 | Production profile disables service-side plaintext upload; formal upload is `/api/data/upload-encrypted`. |
| 9 | DEK/KEK/shared-secret byte arrays are cleared in finally blocks across upload/decrypt/capsule paths. |
| 10 | Demo token now includes issuer, audience, kid, token id, expiration, key rotation, and revocation support. |
| 11 | Object-level authorization remains centralized in `ObjectAuthorizationService`. |
| 12 | Revocation semantics documented; hard revocation requires owner-side rotation of ciphertext/capsule. |
| 13 | Service-side plaintext content-key rotation helper removed from `RevocationService`. |
| 14 | Database schema and initializer added for users/data/grants/packages/nonces/revocations/audit. |
| 15 | Audit proof plus append-only anchor service added. |
| 16 | Audit proof export includes root, Merkle root, event count, and signature verification. |
| 17 | Tenant appears in token/security context/proxy governance and database schema keys. |
| 18 | API has uniform errors, rate limiting, body limit, idempotency key replay guard, and prod/demo separation. |
| 19 | Chunked AES-GCM encryptor added for large-file streaming/manifest workflows. |
| 20 | Attack-oriented test artifacts regenerated under `docs/reports/raw`. |
| 21 | Benchmark artifacts regenerated with current code. |
| 22 | Upstream/originality notice added. |
| 23 | Demo boundaries enforced by profile, route registration, OpenAPI, and tests. |
| 24 | Priority order reflected in code and documentation: hard security boundaries first, then audit/authz/API, then performance/docs. |
