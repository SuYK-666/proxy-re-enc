# Expected Demo Output

实际时间戳和 dataId 会变化，核心验收点如下：

```text
=== RSA-PRE Scenario ===
Alice uploads encrypted file: success
Ciphertext differs from plaintext: true
Bob decrypts before authorization: failed
Proxy re-encrypts capsule: success
Bob decrypts after authorization: success
Charlie decrypts after Bob authorization: failed

=== ECC-PRE Scenario ===
Alice uploads encrypted file: success
Ciphertext differs from plaintext: true
Bob decrypts before authorization: failed
Proxy re-encrypts capsule: success
Bob decrypts after authorization: success
Charlie decrypts after Bob authorization: failed
```
