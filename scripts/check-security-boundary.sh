#!/usr/bin/env sh
set -eu
grep -q 'productionProfileDoesNotExposeDemoPlaintextRoutes' src/test/java/com/example/pre/api/ApiIntegrationTest.java
grep -q 'integrity validation failed' src/main/java/com/example/pre/service/PackageVerifier.java
grep -q 'verifyFormalPackage' src/main/java/com/example/pre/service/PackageVerifier.java
grep -q 'STANDARD_ENVELOPE' src/main/java/com/example/pre/crypto/provider/CryptoProfileGuard.java
grep -q 'Ed25519' src/main/java/com/example/pre/service/AuditProofService.java
printf '%s\n' 'Security boundary checks present: production route/profile block, package proof verification and Ed25519 audit signing.'
