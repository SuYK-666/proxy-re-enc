# Cryptographic Versioning

All issued shared packages use explicit `packageVersion=v2`, `schemeId`,
`parameterSpec` and `keyVersion`. `PackageVerifier` rejects unknown package
versions before integrity or proof processing. Capsules additionally carry the
suite parameter specification and canonical context digest.

Compatibility policy:

- `v2` remains readable while its algorithm suite is enabled for verification.
- New production writes use `SECURE_ENVELOPE_V1`; RSA/ECC package material is
  retained only for demo and measured baseline evidence.
- Unknown versions fail closed with `PACKAGE_INVALID`.
- Content-key rotation increments `keyVersion`; old packages are invalidated
  rather than silently interpreted under the new key.

Evidence: `PackageVerifierTest.rejectsUnknownPackageVersion`,
`KeyLifecycleServiceTest`, and `CryptoProfileGuardTest`.
