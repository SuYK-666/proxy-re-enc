# Security Boundary

## Normal Secure Share Path

1. Owner uploads ciphertext and PRE capsule.
2. Owner creates `ShareGrant` with policy hash.
3. Proxy re-encrypts capsule for an active grant.
4. Recipient downloads package metadata and encrypted payload references.
5. Recipient decrypts on the client side.

The normal `/api/shared-packages/{packageId}` endpoint does not return plaintext.

## Demo-Only Path

`/api/demo/shared-packages/{packageId}/decrypt` returns plaintext only for correctness demonstrations. It is guarded by the same package recipient checks and should be disabled in production profiles.

## Rotation Boundary

`rotateContentKey(...)` is a demo helper that accepts plaintext to show correctness. The formal secure path is `acceptOwnerSideRotation(...)`, where the owner client prepares the new ciphertext and capsule before the server stores the new version.

## Grant Context Boundary

The original DEK capsule is cryptographically bound to owner upload context because the proxy cannot unwrap and re-wrap the DEK. Shared packages additionally store `grantPolicyHash`, `grantContextHash`, and `grantAad` so policy, recipient, grant, and version binding is enforced by service authorization, package status, counters, and audit evidence.
