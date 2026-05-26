#!/usr/bin/env sh
set -eu
for path in \
  README.md docs/doc-index.md docs/traceability-matrix.md docs/architecture.md docs/state-machines.md \
  docs/crypto/algorithm-spec.md docs/crypto/security-boundary.md \
  docs/crypto/envelope-scheme.md docs/crypto/context-binding.md docs/crypto/threshold-re-encryption.md \
  docs/crypto/versioning.md docs/security/attack-test-matrix.md \
  docs/api/authorization-matrix.md docs/api/error-codes.md docs/api/idempotency.md docs/revocation-and-rotation.md docs/audit-proof.md docs/data-model.md \
  docs/experiments/experiment-plan.md docs/experiments/result-report.md docs/experiments/dataset-design.md \
  docs/testing/security-regression.md docs/deployment.md docs/cli-verification.md docs/database-migration.md \
  docs/multi-tenant-isolation.md docs/secure-coding.md \
  docs/architecture/system-architecture.md docs/architecture/state-machines.md \
  docs/algorithms/provider-contract.md docs/algorithms/secure-envelope-provider.md \
  docs/security/security-boundary.md docs/security/revocation-semantics.md docs/security/access-counter.md \
  docs/api/error-model.md docs/api/security-controls.md docs/package-format/v2.md \
  docs/storage/repository-design.md docs/testing/test-plan.md \
  docs/experiments/experiment-design.md docs/ops/ci-quality-gates.md \
  benchmark/datasets/manifest.json docs/crypto/versioning.md docs/security/attack-test-matrix.md
do
  test -f "$path"
done
printf '%s\n' 'Required documentation set is present.'
