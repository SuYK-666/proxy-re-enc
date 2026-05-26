# ReKeyShare Self-Test Report

| Case | Result | Detail |
|---|---|---|
| RSA-PRE Bob authorized decrypt | PASS | plaintext hash matches |
| RSA-PRE Charlie package access | PASS | ACCESS_DENIED |
| RSA-PRE revoked grant | PASS | GRANT_REVOKED |
| RSA-PRE content key rotation | PASS | contentKeyVersion incremented |
| RSA-PRE audit verify | PASS | hash chain valid |
| ECC-PRE Bob authorized decrypt | PASS | plaintext hash matches |
| ECC-PRE Charlie package access | PASS | ACCESS_DENIED |
| ECC-PRE revoked grant | PASS | GRANT_REVOKED |
| ECC-PRE content key rotation | PASS | contentKeyVersion incremented |
| ECC-PRE audit verify | PASS | hash chain valid |
