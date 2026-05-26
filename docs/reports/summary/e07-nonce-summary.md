# E07 Nonce and Replay Boundary

- Commit: `9189d85`
- JDK: `22.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T11:45:38.420659700Z`

The runner reserved 100 unique nonces and rejected a deliberate duplicate; the JUnit concurrency case additionally proves 100 contenders for one nonce produce exactly one accepted reservation.

Raw data: `../raw/e07-nonce-results.json`

Result: **PASS**.
