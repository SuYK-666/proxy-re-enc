# E01 End-to-End Correctness

- Commit: `9189d85`
- JDK: `22.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T11:45:37.758293800Z`

Secure envelope AEAD rounds over 1 KB, 100 KB, 1 MB and 10 MB files: 120; recovered: 120; unauthorized recipient rejected: 120.

RSA/ECC baseline full payload paths are measured by E02 under their documented experimental security boundary.

Raw data: `../raw/e01-secure-envelope-correctness.csv`

Result: **PASS** (success and unauthorized rejection must both be 100%).
