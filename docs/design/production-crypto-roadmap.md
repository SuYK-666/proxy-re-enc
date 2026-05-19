# Production Crypto Roadmap

This repository keeps RSA-PRE and ECC-PRE as teaching prototypes. A production-grade deployment should replace the crypto backend behind `PreScheme` with reviewed libraries.

| Direction | Why It Helps | Integration Point |
|---|---|---|
| HPKE | Mature hybrid public-key encryption building block | Replace DEK encapsulation for direct recipient sharing |
| Threshold / Umbral-style PRE | Collusion-resistant proxy re-encryption with key shares | Implement `PreScheme` with threshold re-encryption keys |
| Pairing-based PRE | Classical PRE construction with formal security proofs | Implement `generateReKey` and `reEncrypt` in a reviewed library wrapper |
| HSM/KMS-backed keys | Strong private-key custody and audit | Replace `DemoPrivateKeyStore` and client simulator |

The management layer is intentionally separated from `PreScheme` so the lifecycle, authorization, audit, benchmark, and API evidence can remain stable while the algorithm provider is replaced.
