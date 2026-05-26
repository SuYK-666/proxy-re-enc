# Revocation And Rotation Report

1. Alice creates an active `ShareGrant` for Bob.
1. Proxy creates a package and Bob decrypts successfully.
1. Alice revokes the grant. Further package access returns `GRANT_REVOKED`.
1. Alice rotates the content key. `contentKeyVersion` increments and previous grants are marked `ROTATED`.
