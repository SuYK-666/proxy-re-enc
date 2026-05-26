# Secure Coding Checklist

- Never log or include plaintext, DEK, private-key material, re-key material, token
  secrets, raw capsule bytes or threshold shares in errors/snapshots.
- Secret-bearing value objects must render `toString()` as `<redacted>`.
- Apply `LogSanitizer` before user-controlled detail enters operational logging.
- Zero temporary byte-array key material where ownership allows it.
- Preserve negative tests for context replacement, proof verification, nonce replay and
  authorization failures on every security-sensitive change.

`LogSanitizerTest` checks both operational string filtering and redacted rendering for
private keys, re-keys, recipient/threshold shares and encrypted capsules.
