# Revocation And Rotation Report

1. Alice creates an active `ShareGrant` for Bob.
2. Proxy creates a package and Bob decrypts successfully.
3. Alice revokes the grant. Further package access returns `GRANT_REVOKED`.
4. Alice rotates the content key. `contentKeyVersion` increments and previous grants are marked `ROTATED`.
