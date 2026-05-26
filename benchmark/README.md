# Benchmark Inputs

`datasets/manifest.json` defines the deterministic non-cryptographic plaintext generator for
E02. During execution, `BenchmarkApplication` writes canonical size/hash
evidence to `docs/reports/raw/dataset-manifest.json`. Cryptographic keys and
nonces remain generated from cryptographic randomness by design; the input data profile is reproducible.

E03 separately verifies streamed 100 MB inputs because its purpose is bounded
memory and chunk integrity rather than PRE baseline latency.
