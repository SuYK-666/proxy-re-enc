$ErrorActionPreference = 'Stop'

$started = Get-Date
$commit = git rev-parse HEAD
$report = 'docs/reports/final-verification.md'

mvn verify
if ($LASTEXITCODE -ne 0) { throw "mvn verify failed with exit code ${LASTEXITCODE}" }
powershell -ExecutionPolicy Bypass -File scripts/check-security-boundary.ps1
if ($LASTEXITCODE -ne 0) { throw "security boundary gate failed with exit code ${LASTEXITCODE}" }
powershell -ExecutionPolicy Bypass -File scripts/run-all-experiments.ps1
if ($LASTEXITCODE -ne 0) { throw "experiment runner failed with exit code ${LASTEXITCODE}" }
powershell -ExecutionPolicy Bypass -File scripts/check-doc-links.ps1
if ($LASTEXITCODE -ne 0) { throw "documentation gate failed with exit code ${LASTEXITCODE}" }
powershell -ExecutionPolicy Bypass -File scripts/check-performance-budget.ps1
if ($LASTEXITCODE -ne 0) { throw "performance gate failed with exit code ${LASTEXITCODE}" }

$completed = Get-Date
$jdk = cmd /c 'java -version 2>&1' | Select-Object -First 1
$lines = @(
  '# Final Verification',
  '',
  "- Commit: ``$commit``",
  "- Executed at: ``$($completed.ToString('o'))``",
  "- Duration seconds: ``$([math]::Round(($completed - $started).TotalSeconds, 2))``",
  "- Java: ``$jdk``",
  '- Build/unit/integration/security/static-quality gates (`mvn verify`): `PASS`',
  '- Security boundary gate: `PASS`',
  '- Reproducible experiment runner: `PASS`',
  '- Documentation links and performance budget: `PASS`',
  '',
  'Raw experiment evidence is preserved under `docs/reports/raw/`; interpreted summaries are under `docs/reports/summary/`.',
  'Deployment-scoped integrations (KMS/HSM, OIDC/mTLS, WORM anchor, durable multi-instance runtime wiring) remain explicit boundaries.'
)
Set-Content -Encoding UTF8 -Path $report -Value $lines
Write-Host "Verification report: $report"
