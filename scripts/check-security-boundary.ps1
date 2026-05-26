$ErrorActionPreference = 'Stop'

$productionTest = Select-String -Path 'src/test/java/com/example/pre/api/ApiIntegrationTest.java' -Pattern 'productionProfileDoesNotExposeDemoPlaintextRoutes'
$v2Verifier = Select-String -Path 'src/main/java/com/example/pre/service/PackageVerifier.java' -Pattern 'integrity validation failed'
if (-not $productionTest -or -not $v2Verifier) {
    throw 'Required security boundary enforcement or tests are missing.'
}
Write-Host 'Security boundary checks present: production plaintext route block and package verifier.'
