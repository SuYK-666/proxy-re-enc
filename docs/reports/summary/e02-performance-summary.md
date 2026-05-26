# Performance Summary

Source: `../raw/e02-algorithm-benchmark.csv`

Formal experiment settings: warmup=20 and measurement=100 per algorithm/file
size; JUnit may override these values for schema smoke checks.

| Algorithm | File Size | Avg Total Ms | P50 | P95 | P99 | Stddev | Throughput B/s | Avg AES Encrypt Ms | Avg AES Decrypt Ms | Avg ReEncrypt Ms | Capsule Bytes | Success |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| RSA-PRE | 1024 | 20.2136 | 19.8316 | 23.0964 | 27.3689 | 2.2821 | 50659.03 | 2.2081 | 0.0571 | 6.9979 | 444 | PASS |
| RSA-PRE | 102400 | 20.2935 | 20.1582 | 22.1471 | 23.3284 | 1.0837 | 5045953.66 | 2.9945 | 0.9977 | 6.4576 | 444 | PASS |
| RSA-PRE | 1048576 | 21.7855 | 21.6723 | 23.3515 | 24.4947 | 0.8202 | 48131934.64 | 3.8162 | 1.8018 | 6.4127 | 444 | PASS |
| RSA-PRE | 10485760 | 24.6786 | 24.3690 | 27.3378 | 29.5056 | 1.3871 | 424892340.04 | 5.1237 | 3.0700 | 6.4063 | 444 | PASS |
| ECC-PRE | 1024 | 25.4091 | 25.0514 | 26.9932 | 29.4786 | 1.3568 | 40300.48 | 2.0153 | 0.0062 | 3.5649 | 125 | PASS |
| ECC-PRE | 102400 | 25.2561 | 25.1252 | 26.2677 | 28.0533 | 1.0429 | 4054464.93 | 2.0875 | 0.0419 | 3.6143 | 125 | PASS |
| ECC-PRE | 1048576 | 26.0673 | 25.8920 | 27.6190 | 30.2184 | 1.1634 | 40225697.18 | 2.5104 | 0.3211 | 3.5442 | 125 | PASS |
| ECC-PRE | 10485760 | 31.9716 | 31.6445 | 34.0373 | 41.2216 | 1.7997 | 327970756.32 | 5.2761 | 3.0843 | 3.6198 | 125 | PASS |

The CSV remains the source of truth; this summary is generated from the same rows.

## Analysis

Correctness passed for every measured row. On a warmed JVM with CPU AES
acceleration, AES-GCM throughput can be faster than the conservative planning
interval; lower latency is not a regression when authentication and recovery
checks remain successful. RSA/ECC values are baseline comparison data only and
do not change their experimental security status.
