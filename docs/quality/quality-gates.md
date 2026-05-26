# Quality Gates

This document explains the status badges in README and how they map to the
quality requirements enforced by CI.

## Badge Mapping

- Commit: points to the latest commit on main.
- CI: reflects the Backend CI workflow for build, tests, and evidence runs.
- Coverage (JaCoCo gate): indicates the JaCoCo thresholds enforced in CI.
- SBOM (CycloneDX): indicates SBOM generation and verification in CI.

## Gate Sources

- CI workflow: .github/workflows/backend-ci.yml
- Quality requirements: docs/ops/ci-quality-gates.md

## Evidence Artifacts

The CI workflow uploads:

- docs/reports/raw
- docs/reports/summary
- target/site/jacoco
- target/bom.json
- target/surefire-reports
