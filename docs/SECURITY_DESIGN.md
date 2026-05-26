# ReKeyShare Security Design

## Identity

Formal API paths require `Authorization: Bearer <signed-token>`. The signed demo
token carries `sub`, `role`, `iat`, `exp`, `jti`, and `tenantId`; `X-Actor-Id`
and body `actorId/userId` are not trusted by default.

## Client-Side Encryption Path

The production upload path is `/api/data/upload-encrypted`:

1. Owner client generates a DEK.
1. Owner client encrypts plaintext with AES-GCM.
1. Owner client encapsulates the DEK into a PRE capsule.
1. Server stores only ciphertext, nonce, AAD, capsule, and metadata.

The legacy `/api/data/upload` plaintext path is retained as a demo/test fixture only.
Even on demo paths, the persisted business model does not retain plaintext bytes
or plaintext-derived demo hashes. `EncryptedDataPackage` stores only ciphertext,
nonce, AAD, capsule material, hashes of ciphertext/AAD context, and non-sensitive
metadata such as original size.

## Sharing Path

1. Owner creates a grant bound to `dataId`, recipient, policy hash, and content-key version.
1. A registered ACTIVE proxy node with role `PROXY` transforms the owner capsule.
1. Recipient downloads ciphertext materials from `/api/shared-packages/{id}`.
1. Recipient decrypts locally with their private key and AES-GCM.

The formal package response does not include a `plaintext` field.

## Cryptographic Scheme Boundary

`RSA_PRE` and `ECC_PRE` are baseline/demo schemes only. The production
cryptographic commitment is client-side AEAD encryption plus a replaceable,
reviewed envelope/PRE layer. See `docs/CRYPTO_SCHEME.md`.

## Revocation And Rotation

Revoking a grant marks the grant as revoked and invalidates all related
packages. Owner-side content-key rotation invalidates old grants/packages and
stores a new encrypted version without server plaintext handling.

## Audit

Audit records form a hash chain. `AuditProofService` creates a signed checkpoint
over chain root, Merkle root, and event count. Verification detects field edits,
deletion, reordering, and unsigned full-chain rewrites.

## Policy Enforcement

`AccessPolicy` enforces allowed actions, max access, max re-encryption, max
download, max decrypt, and expiration. Download and re-encryption check/update
sequences are synchronized for in-memory consistency.

## Proxy Governance

Proxy nodes are represented by `ProxyNode` and governed by `ProxyNodeService`.
Nodes can be registered and revoked; formal re-encryption requires both token
role `PROXY` and ACTIVE node status.
