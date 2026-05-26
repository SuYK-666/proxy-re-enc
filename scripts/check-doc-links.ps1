$ErrorActionPreference = 'Stop'
$required = @(
  'README.md',
  'docs/doc-index.md',
  'docs/traceability-matrix.md',
  'docs/architecture/system-architecture.md',
  'docs/architecture/state-machines.md',
  'docs/algorithms/provider-contract.md',
  'docs/algorithms/secure-envelope-provider.md',
  'docs/security/security-boundary.md',
  'docs/security/revocation-semantics.md',
  'docs/security/access-counter.md',
  'docs/api/error-model.md',
  'docs/api/security-controls.md',
  'docs/package-format/v2.md',
  'docs/storage/repository-design.md',
  'docs/testing/test-plan.md',
  'docs/experiments/experiment-design.md',
  'docs/ops/ci-quality-gates.md'
)
foreach ($path in $required) {
  if (-not (Test-Path $path)) { throw "Missing required document: $path" }
}
Write-Host "Required documentation set is present ($($required.Count) files)."
