#!/usr/bin/env sh
set -eu

commit="$(git rev-parse HEAD)"
mvn verify
sh scripts/check-security-boundary.sh
sh scripts/run-all-experiments.sh
sh scripts/check-doc-links.sh
sh scripts/check-performance-budget.sh

cat > docs/reports/final-verification.md <<EOF
# Final Verification

- Commit: \`$commit\`
- Build/unit/integration/security/static-quality gates (\`mvn verify\`): \`PASS\`
- Security boundary gate: \`PASS\`
- Reproducible experiment runner: \`PASS\`
- Documentation links and performance budget: \`PASS\`

Raw experiment evidence is preserved under \`docs/reports/raw/\`; interpreted summaries are under \`docs/reports/summary/\`.
Deployment-scoped integrations (KMS/HSM, OIDC/mTLS, WORM anchor, durable multi-instance runtime wiring) remain explicit boundaries.
EOF
printf '%s\n' 'Verification report: docs/reports/final-verification.md'
