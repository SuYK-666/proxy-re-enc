# Proxy Re-Encryption Data Security Demo

Java implementation of a course-oriented proxy re-encryption (PRE) data sharing system.

The project implements:

1. RSA-PRE teaching prototype with shared RSA modulus and non-trivial shared public exponent factor.
2. ECC-PRE teaching prototype over P-256 with interactive re-encryption key generation.
3. AES-256-GCM hybrid encryption for file/content confidentiality.
4. End-to-end data sharing scenario: Alice uploads encrypted data, proxy transforms the key capsule, Bob decrypts, Charlie fails.
5. JUnit tests for correctness, unauthorized access, tamper detection, and benchmark generation.

## Run

This project requires Java 17 and Maven.

```bash
mvn test
mvn exec:java -Dexec.mainClass=com.example.pre.app.DemoApplication
mvn exec:java -Dexec.mainClass=com.example.pre.app.BenchmarkApplication
```

Generated outputs:

```text
demo/output/demo-result.txt
docs/reports/performance-results.csv
```

## Important Security Note

Both RSA-PRE and ECC-PRE are teaching prototypes. They are designed to explain the PRE workflow and compare algorithmic costs, not to provide production-grade PRE security.

Production systems should use reviewed schemes such as Umbral-style threshold PRE or pairing-based PRE, together with mature key management, identity binding, revocation, and audited cryptographic libraries.
