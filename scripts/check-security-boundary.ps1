$ErrorActionPreference = 'Stop'

$productionTest = Select-String -Path 'src/test/java/com/example/pre/api/ApiIntegrationTest.java' -Pattern 'productionProfileDoesNotExposeDemoPlaintextRoutes'
$v2Verifier = Select-String -Path 'src/main/java/com/example/pre/service/PackageVerifier.java' -Pattern 'integrity validation failed'
$proofVerifier = Select-String -Path 'src/main/java/com/example/pre/service/PackageVerifier.java' -Pattern 'verifyFormalPackage'
$profileGuard = Select-String -Path 'src/main/java/com/example/pre/crypto/provider/CryptoProfileGuard.java' -Pattern 'STANDARD_ENVELOPE'
$auditEd25519 = Select-String -Path 'src/main/java/com/example/pre/service/AuditProofService.java' -Pattern 'Ed25519'
if (-not $productionTest -or -not $v2Verifier -or -not $proofVerifier -or -not $profileGuard -or -not $auditEd25519) {
    throw 'Required security boundary enforcement or tests are missing.'
}
Write-Host 'Security boundary checks present: production route/profile block, package proof verification and Ed25519 audit signing.'
