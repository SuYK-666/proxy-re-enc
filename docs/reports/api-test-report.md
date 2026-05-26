# API Test Report

## Latest Result

```text
TestSuiteRunner: Tests run: 50, Failures: 0
```

## Covered API Security Features

| Feature | Status |
|---|---|
| Signed demo bearer token | PASS |
| Legacy `X-Actor-Id` disabled in API state | PASS |
| RSA/ECC scheme registry | PASS |
| ECC rekey session + recipient-share API | PASS |
| Protected API rejects missing token | PASS |
| Object-level authorization for `dataId` | PASS |
| Object-level authorization for `packageId` | PASS |
| Proxy role required for re-encrypt | PASS |
| Admin role required for audit/benchmark/storage | PASS |
| Normal shared package does not return plaintext | PASS |
| Demo decrypt route isolated under `/api/demo/**` | PASS |
| `/api/audit/proof` exports Merkle proof | PASS |
| `/api/benchmark/summary` returns structured CSV summary | PASS |
| `/api/storage/export-index` writes repository-like JSON files and manifest | PASS |

## BOLA Negative Case

Charlie attempts to access Bob's package:

```text
GET /api/shared-packages/{bobPackageId}
Authorization: Bearer <charlie-token>
```

Expected result:

```text
HTTP 403
ACCESS_DENIED
```

## Notes

The API remains a no-external-dependency JDK `HttpServer` implementation for
course reproducibility. The production upgrade path is Spring Boot/JPA/H2 or
SQLite with a full generated OpenAPI schema.
