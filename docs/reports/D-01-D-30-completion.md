# D-01 to D-30 Completion Notes

| ID | Status | Evidence |
|---|---|---|
| D-01 | Done | Signed bearer tokens, `SecurityContext`, 401 on unauthenticated requests. |
| D-02 | Done | `/api/shared-packages/{id}` returns ciphertext/capsule only; plaintext only under demo decrypt endpoint. |
| D-03 | Done | `/api/data/upload-encrypted`, `uploadEncrypted`, owner-side rotation path; package model no longer accepts or stores plaintext/demo plaintext hashes. |
| D-04 | Done | Production RSA generator rejects <2048 bit; default is 3072 bit. |
| D-05 | Done | `THREAT_MODEL.md` and README classify RSA-PRE as teaching prototype. |
| D-06 | Done | Threat model marks self-written ECC as demo-only/out-of-production boundary. |
| D-07 | Done | KDF compatibility entry now uses HKDF-SHA256 extract/expand. |
| D-08 | Done | Capsule context hash validation and ECC context tests remain in `crypto` tests. |
| D-09 | Done | Packages validate grant policy hash, context hash, recipient, and content-key version. |
| D-10 | Done | Formal proxy path uses token role `PROXY` and `SecurityContext`. |
| D-11 | Done | Revoke invalidates related packages. |
| D-12 | Done | Access, re-encrypt, download, decrypt, expiration, and allowed-action policy checks. |
| D-13 | Done | Download/re-encrypt check-and-count paths are synchronized. |
| D-14 | Done | JSON snapshot export/import and H2 audit repository exist; transaction caveat documented. |
| D-15 | Done | Hash chain plus signed proof/checkpoint verification. |
| D-16 | Done | Hardened JSON parser path, uniform 400, body-size guard. |
| D-17 | Done | Uniform error JSON and lightweight failure rate limiter. |
| D-18 | Done | User key rotation creates new keypairs; owner-side content-key rotation supported. |
| D-19 | Done | Token includes tenantId; proxy nodes can be tenant-scoped. |
| D-20 | Done | Ciphertext metadata includes storage path and hashes; snapshot export preserves objects. |
| D-21 | Done | AES-GCM 12-byte nonce and nonce manager tests. |
| D-22 | Done | DEKs are zeroed after upload/rotation use; logs avoid plaintext/DEK; encrypted package/data object models contain no plaintext or plaintext hash fields. |
| D-23 | Done | OpenAPI includes security scheme, errors, upload-encrypted, proxy governance. |
| D-24 | Done | Security/API/negative/scenario/performance tests and raw report directories. |
| D-25 | Done | Benchmark CSV and summary include latency, throughput, size, success. |
| D-26 | Done | CI includes test, verify, SpotBugs, dependency-check, JaCoCo. |
| D-27 | Done | `docs/THREAT_MODEL.md` added. |
| D-28 | Done | `ProxyNode` and `ProxyNodeService` with register/revoke/audit. |
| D-29 | Done | Token `jti/exp`, package status, content-key version and context replay checks. |
| D-30 | Done | Sensitive-field policy documented; audit retention vs demo deletion boundary stated. |
