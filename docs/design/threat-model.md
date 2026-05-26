# Threat Model

## Roles

| Role | Capability | Boundary |
|---|---|---|
| Owner | Upload encrypted data, create grants, revoke grants, rotate content keys | Owns original data and private key |
| Recipient | Download shared package metadata, locally decrypt authorized data, submit ECC recipient share | Cannot access other recipients' packages |
| Proxy | Transform PRE capsule for active grants | Cannot see plaintext or DEK |
| Admin | Verify/export audit and benchmark evidence | Cannot bypass cryptographic checks |
| Attacker | Guess object ids, replay old packages, tamper metadata, forge identity | Blocked by token auth, object authorization, AAD/context checks, audit |

## STRIDE Summary

| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Fake `X-Actor-Id` | Signed demo bearer token; legacy header disabled |
| Tampering | Modify ciphertext/capsule/audit action | AES-GCM tag, capsule context hash, audit hash chain |
| Repudiation | Deny revoke/download action | Audit event hash chain and proof export |
| Information disclosure | Charlie guesses Bob package id | Object-level authorization |
| Denial of service | Exhaust grant counters | Policy counters and explicit errors |
| Elevation of privilege | Normal user calls proxy endpoint | Proxy role check and bearer token identity |

## Explicit Security Boundary

RSA-PRE and ECC-PRE are teaching prototypes. The system demonstrates lifecycle
management, object authorization, revocation, audit, and benchmark evidence.
Production deployment should replace the PRE algorithms with reviewed
PRE/HPKE/threshold PRE libraries and store private keys in client/HSM custody.
