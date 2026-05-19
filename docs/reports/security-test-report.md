# Security Test Report

| Attack | Expected | Result |
|---|---|---|
| Charlie downloads Bob packageId | ACCESS_DENIED | PASS |
| Bob uses revoked grant | GRANT_REVOKED | PASS |
| Expired grant re-encryption | GRANT_EXPIRED | covered by JUnit |
| AES-GCM ciphertext/AAD/wrong key tamper | decrypt failure | covered by JUnit |
| Audit action tamper | invalid hash chain | PASS |
