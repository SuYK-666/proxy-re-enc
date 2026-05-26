# E03 Chunked AEAD Scalability

- Commit: `9189d85`
- JDK: `22.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T11:46:08.330777800Z`

The streaming pipeline measured 30 runs each for 1 MB, 10 MB and 100 MB ciphertext streams. The reproducible runner executes this experiment in a warmed `-Xmx12m` child JVM with a 128 KiB plaintext chunk. Raw rows record an observed heap peak delta and the configured plaintext buffer. Measurements use natural JVM collection behavior after warmup; observations include GC sampling noise and are interpreted with that constraint stated.

| File size | Max observed heap delta / file | Interpretation |
| ---: | ---: | --- |
| 1 MB | 525.0237% | fixed JVM overhead dominates |
| 10 MB | 58.6217% | planning range not met on this JVM |
| 100 MB | 5.4145% | PASS strict `<20%` gate |

Tamper evidence: modification, deletion, reordering and AAD/context replacement were rejected (4/4).

Raw data: `../raw/e03-chunked-aead-results.csv`, `../raw/e03-chunk-integrity-results.json`

Result: **PASS** (100 MB streamed verification and integrity matrix completed).
