# Performance Summary

Source: `../raw/e02-algorithm-benchmark.csv`

Formal experiment settings: warmup=20 and measurement=100 per algorithm/file size; JUnit may override these values for schema smoke checks.

| Algorithm | File Size | Avg Total Ms | P50 | P95 | P99 | Stddev | Throughput B/s | Avg AES Encrypt Ms | Avg AES Decrypt Ms | Avg ReEncrypt Ms | Capsule Bytes | Success |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| RSA-PRE | 1024 | 21.6222 | 21.4674 | 24.0401 | 26.8281 | 1.5264 | 47358.83 | 0.8125 | 0.0675 | 8.6073 | 444 | PASS |
| RSA-PRE | 102400 | 23.3421 | 22.9365 | 25.7109 | 31.7757 | 1.7570 | 4386923.39 | 2.0344 | 1.3095 | 8.5161 | 444 | PASS |
| RSA-PRE | 1048576 | 24.7163 | 24.4862 | 28.0991 | 29.9411 | 1.8915 | 42424400.83 | 2.8176 | 2.1529 | 8.4263 | 444 | PASS |
| RSA-PRE | 10485760 | 27.2846 | 26.7660 | 31.5175 | 32.2755 | 2.1662 | 384311197.31 | 4.3473 | 3.3358 | 8.3299 | 444 | PASS |
| ECC-PRE | 1024 | 32.0266 | 31.7522 | 35.0441 | 38.1749 | 2.0212 | 31973.44 | 0.6970 | 0.0074 | 5.1049 | 125 | PASS |
| ECC-PRE | 102400 | 30.7291 | 30.4684 | 32.7190 | 37.1411 | 1.5069 | 3332350.44 | 0.7033 | 0.0520 | 4.9116 | 125 | PASS |
| ECC-PRE | 1048576 | 31.3913 | 30.9995 | 35.2526 | 36.9349 | 1.9029 | 33403438.84 | 1.0139 | 0.3524 | 4.9031 | 125 | PASS |
| ECC-PRE | 10485760 | 37.0183 | 36.6320 | 40.5805 | 42.9232 | 1.6159 | 283259119.06 | 4.0694 | 3.2760 | 4.8376 | 125 | PASS |

The CSV remains the source of truth; this summary is generated from the same rows.

## Analysis

Correctness passed for every measured row. On a warmed JVM with CPU AES acceleration, AES-GCM throughput can be faster than the conservative planning interval; lower latency is not a regression when authentication and recovery checks remain successful. RSA/ECC values are baseline comparison data only and do not change their experimental security status.
