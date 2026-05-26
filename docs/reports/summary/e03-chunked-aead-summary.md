# E03 Chunked AEAD Scalability

- Commit: `a85e36f`
- JDK: `25.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T06:34:37.538652600Z`

The 1 MB chunk pipeline verified 1 MB, 10 MB and 100 MB ciphertext streams.
The working plaintext buffer is bounded by the configured 1 MB chunk size.

Raw data: `../raw/e03-chunked-aead-results.csv`

Result: **PASS** (100 MB streamed verification completed).
