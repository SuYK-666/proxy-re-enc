# CLI Verification

The offline verifier provides JSON results without starting the HTTP server:

```powershell
mvn -q -DskipTests compile
mvn -q -Dexec.mainClass=com.example.pre.app.VerificationCli -Dexec.args="crypto verify-envelope" exec:java
mvn -q -Dexec.mainClass=com.example.pre.app.VerificationCli -Dexec.args="audit verify" exec:java
mvn -q -Dexec.mainClass=com.example.pre.app.VerificationCli -Dexec.args="attack-matrix check" exec:java
```

`crypto verify-envelope` performs a formal `SECURE_ENVELOPE_V1` round trip and
an authenticated-context tamper rejection. `audit verify` checks a hash chain
and Ed25519 checkpoint proof. `attack-matrix check` ensures the maintained
security mapping contains at least 30 scenarios.

The CLI is an offline verification entry point; importing externally provisioned
KMS signing keys or production database exports remains deployment integration.
