# E01 End-to-End Correctness

- Commit: `a85e36f`
- JDK: `25.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T06:34:34.738687800Z`

Secure envelope AEAD rounds over 1 KB, 100 KB, 1 MB and 10 MB files: 20; recovered: 20; unauthorized recipient rejected: 20.

RSA/ECC baseline full payload paths are measured by E02 under their documented experimental security boundary.

Raw data: `../raw/e01-secure-envelope-correctness.csv`

Result: **PASS** (success and unauthorized rejection must both be 100%).
