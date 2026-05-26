#!/usr/bin/env sh
set -eu
grep -q 'productionProfileDoesNotExposeDemoPlaintextRoutes' src/test/java/com/example/pre/api/ApiIntegrationTest.java
grep -q 'integrity validation failed' src/main/java/com/example/pre/service/PackageVerifier.java
printf '%s\n' 'Security boundary checks present: production plaintext route block and package verifier.'
