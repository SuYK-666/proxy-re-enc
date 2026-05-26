# Dataset Design

`ReproducibleDataset` generates plaintext fixtures only; cryptographic keys and nonces
remain security-random. The fixed seed and round derivation allow a reviewer to regenerate
inputs and compare the SHA-256 values in `reports/raw/dataset-manifest.json`.

| Distribution | Intent |
| --- | --- |
| `deterministic-random` | High-entropy-like baseline used for E02 algorithm comparison |
| `zero-heavy` | Sparse payload with one nonzero byte per 16-byte region |
| `text-json` | Repeated structured text records |
| `binary-image-like` | Repeated gradient-like binary byte pattern |
| `compressible` | Highly repeated application payload |

E15 runs each distribution at 1 MiB for 30 samples and publishes raw per-sample hashes and
latencies. AES-GCM does not compress plaintext; distribution comparison therefore detects
unexpected implementation sensitivity, not a compression-performance claim.
