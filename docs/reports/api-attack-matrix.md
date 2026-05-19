# API Attack Matrix

| Attack | Expected Result | Evidence |
|---|---|---|
| Missing bearer token calls protected API | HTTP 403 `ACCESS_DENIED` | `ApiIntegrationTest.protectedApiRejectsMissingBearerToken` |
| Charlie guesses Alice `dataId` | HTTP 403 `ACCESS_DENIED` | API integration flow |
| Charlie guesses Bob `packageId` | HTTP 403 `ACCESS_DENIED` | API integration flow |
| Bob creates grant for Alice data | HTTP 403 `ACCESS_DENIED` | API integration flow |
| Proxy uses revoked grant | HTTP 403 `GRANT_REVOKED` | API integration flow |
| ECC grant without verified recipient share | HTTP 400/403 | session/share API design |
| Wrong recipient-share challenge/signature | rejected | `EccRecipientShareServiceTest` |
| Download disabled but decrypt allowed | download denied; decrypt allowed | `PolicyActionAuthorizationTest` |

This matrix targets IDOR/BOLA-style attacks and privilege confusion in the management API.
