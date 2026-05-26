# RSA vs ECC Benchmark

RSA-PRE and ECC-PRE are measured through the same lifecycle: key generation,
AES encryption, PRE encapsulation, re-key generation, proxy re-encryption,
decapsulation, and AES decryption.

The PRE stages process the 32-byte DEK capsule, so their cost is mostly independent of plaintext size. AES-GCM stages scale with file size.

See `e02-performance-summary.md` for the generated aggregation table.

## Parameters

| Item | Value |
|---|---|
| RSA | `RSA-PRE-demo-common-modulus-3072` |
| ECC | `ECC-PRE-P-256-demo` |
| AES | AES-256-GCM, 12-byte nonce, 128-bit tag |
| File sizes | 1KB, 100KB, 1MB, 10MB |
| Measurement rounds | 100 per algorithm/size |
| Warmup | 20 per algorithm/size |
| Java observed in this run | Java 25.0.2 |
| Recommended reproducible runtime | Java 17 LTS |
