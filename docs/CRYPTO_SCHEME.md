# Cryptographic Scheme Position

## Formal Security Commitment

The current RSA-PRE and ECC-PRE implementations are **baseline/demo algorithms**.
They are useful for explaining proxy re-encryption workflow, policy binding,
revocation, and audit behavior, but they are not claimed as production-grade PRE.

The formal production direction for this project is:

1. client-side content encryption with AES-GCM or a streaming AEAD construction;
1. server-side storage of ciphertext, nonce/AAD, capsule/envelope, hashes, and
	metadata only;
1. replacement of teaching PRE with a reviewed scheme such as HPKE (RFC 9180),
	a threshold PRE construction, an Umbral-style PRE construction, or another
	publicly reviewed library.

## Security Model To Use For A Production Replacement

A production replacement must document:

- adversary capabilities: malicious storage, curious proxy, revoked recipient,
	cross-tenant object guessing, audit-storage tampering;
- security goal: at least IND-CPA for envelopes, preferably CCA-secure KEM/AEAD
	composition for active attackers;
- collusion boundary: whether proxy + recipient, old recipient + proxy, or owner
	compromise are in scope;
- key exposure boundary: which private keys remain client-side/KMS/HSM-side and
	which materials may appear on the server;
- revocation semantics: future-access blocking versus impossible recovery of
	already-downloaded plaintext;
- proof or review basis: paper, standard, or audited library version.

## Baseline Algorithm Restrictions

- `RSA_PRE` uses a common-modulus teaching construction and is only a benchmark/demo baseline.
- `ECC_PRE` uses a self-written P-256 teaching implementation and a masked recipient-share flow; it is still not a production PRE proof.
- Production profile disables plaintext demo upload/decrypt routes. Teaching
	algorithms must not be described as the system's production security
	guarantee.
