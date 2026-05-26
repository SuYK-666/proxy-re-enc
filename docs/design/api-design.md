# API Design

## Authentication

Protected endpoints require:

```text
Authorization: Bearer <demo-token>
```

`POST /api/auth/login` issues a signed demo token containing `userId`, `role`, and `expiresAt`.

## Core APIs

| API | Purpose |
|---|---|
| `POST /api/users` | Create demo user and keypair |
| `POST /api/auth/login` | Issue signed demo token |
| `POST /api/data/upload` | Upload encrypted data demo input |
| `GET /api/data/{dataId}` | Read data metadata after object authorization |
| `POST /api/grants` | RSA grant creation |
| `POST /api/rekey-sessions` | Create ECC recipient-share session |
| `POST /api/rekey-sessions/{sessionId}/recipient-share` | Submit signed ECC share |
| `POST /api/grants/ecc` | Complete ECC grant from verified share |
| `POST /api/proxy/re-encrypt` | Proxy capsule transform |
| `GET /api/shared-packages/{packageId}` | Download encrypted package metadata |
| `GET /api/demo/shared-packages/{packageId}/decrypt` | Demo-only plaintext verification |
| `GET /api/audit/proof` | Export chain root, Merkle root, and signature |

## Error Shape

```json
{
  "code": "ACCESS_DENIED",
  "message": "signed bearer token is required"
}
```
