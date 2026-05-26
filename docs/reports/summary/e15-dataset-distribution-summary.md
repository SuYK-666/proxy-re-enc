# E15 Dataset Distribution Comparison

- Commit: `9189d85`
- JDK: `22.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T11:45:37.764234900Z`

Five reproducible plaintext distributions were measured at 1 MB for 30 samples each. AES-GCM does not compress input, so this evidence measures distribution sensitivity without treating compressibility as a security gain.

| Distribution | Samples | Mean Encrypt Ms | Mean Decrypt Ms | Success |
| --- | ---: | ---: | ---: | --- |
| deterministic-random | 30 | 0.9208 | 0.3543 | PASS |
| zero-heavy | 30 | 0.9802 | 0.4042 | PASS |
| text-json | 30 | 0.7741 | 0.3215 | PASS |
| binary-image-like | 30 | 0.9447 | 0.3419 | PASS |
| compressible | 30 | 0.8792 | 0.3445 | PASS |

Raw data: `../raw/e15-dataset-distribution-results.csv`

Result: **PASS** (all distributions recovered correctly).
