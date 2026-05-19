# ReKeyShare Threat Model

## Security Goals

- G-01 Data confidentiality: storage, proxy nodes, and unauthorized users must not recover plaintext or DEKs.
- G-02 Authorization integrity: only owners create grants; only recipients use grants; proxy nodes only transform capsules.
- G-03 Proxy least knowledge: proxy nodes never receive plaintext, DEKs, owner private keys, or recipient private keys.
- G-04 Revocation: revoked grants cannot create new valid packages, and existing packages are invalidated.
- G-05 Verifiable audit: grant, re-encryption, download, revoke, failure, and admin operations are hash chained and checkpointed.
- G-06 Reproducibility: build, self-test, benchmark, and raw reports are kept under `docs/reports`.

## Trust Assumptions

- Signed bearer tokens are issued by the service secret and include `sub`, `role`, `iat`, `exp`, `jti`, and `tenantId`.
- Recipient private keys are client-side assets in the intended production boundary. Demo fixtures are not a production boundary.
- RSA-PRE and ECC-PRE are teaching prototypes. They are retained for demonstration and comparison, not claimed as production-grade PRE.
- Production deployments must replace demo signing secrets and demo key stores.

## In Scope Threats

- Header/body identity spoofing.
- Token tampering and expired-token use.
- Unauthorized recipient/package access.
- Revoked grant/package replay.
- Old content-key-version replay.
- Capsule context tampering.
- Audit record modification, deletion, reordering, and unsigned whole-chain rewriting.
- High-frequency failed authentication/authorization requests.
- Path traversal and ciphertext object tampering at the storage boundary.

## Out Of Scope / Not Guaranteed

- Side-channel resistance of the self-written ECC implementation.
- CCA-secure, collusion-resistant production PRE security for the teaching RSA/ECC schemes.
- Confidentiality if a user's client private key is compromised.
- Availability under large-scale DDoS beyond the built-in lightweight rate limiter.

## Required Production Replacements

- Replace teaching PRE with a reviewed PRE/KEM-envelope scheme.
- Replace demo token secret and demo private-key fixtures.
- Use durable storage with transactional isolation and encrypted object storage.
- Anchor audit checkpoints externally.
