# Idempotency

HTTP write requests accept `Idempotency-Key`. `IdempotencyService` scopes a record to
`actor + action + resource + key` and binds it to a body hash:

| Retry case | Result |
| --- | --- |
| Same key and same request hash | Replay the original status and response body |
| Same key and different request hash | `IDEMPOTENCY_CONFLICT` |
| Record after TTL expiry | May execute as a new request |

`ApiIntegrationTest.replayedIdempotencyKeyDoesNotCreateDuplicateMutation` verifies the
HTTP behavior and avoids duplicate upload mutations. The in-process implementation is the
executable default; multi-instance deployments must back this contract with
`idempotency_records` in `schema.sql`.
