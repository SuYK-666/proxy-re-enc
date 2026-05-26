$ErrorActionPreference = 'Stop'
$commit = git rev-parse --short HEAD

function Invoke-Maven {
  & mvn @args
  if ($LASTEXITCODE -ne 0) {
    throw "Maven command failed with exit code ${LASTEXITCODE}: mvn $args"
  }
}

Invoke-Maven -q "-Drekeyshare.nonce.registry=target/experiment/test-aes-gcm-nonces.txt" test
Invoke-Maven -q -DskipTests compile
Invoke-Maven -q "-Dexec.mainClass=com.example.pre.app.BenchmarkApplication" "-Drekeyshare.nonce.registry=target/experiment/aes-gcm-nonces.txt" exec:java
Invoke-Maven -q "-Dexec.mainClass=com.example.pre.app.EvidenceExperimentApplication" "-Dexec.args=" "-Drekeyshare.commit=$commit" "-Drekeyshare.e03.defer=true" exec:java
& java -Xmx12m "-Drekeyshare.e03.only=true" "-Drekeyshare.e03.chunkBytes=131072" "-Drekeyshare.nonce.registry=target/experiment/e03-aes-gcm-nonces.txt" "-Drekeyshare.commit=$commit" -cp target/classes com.example.pre.app.EvidenceExperimentApplication
if ($LASTEXITCODE -ne 0) {
  throw "Streaming evidence child JVM failed with exit code ${LASTEXITCODE}"
}
Invoke-Maven -q "-Dexec.mainClass=com.example.pre.app.ConcurrencyExperimentApplication" "-Drekeyshare.nonce.registry=target/experiment/aes-gcm-nonces.txt" "-Drekeyshare.commit=$commit" exec:java
Invoke-Maven -q "-Dexec.mainClass=com.example.pre.app.ComplianceExperimentApplication" "-Drekeyshare.commit=$commit" exec:java

Write-Host "Raw evidence: docs/reports/raw/"
Write-Host "Summaries: docs/reports/summary/"
