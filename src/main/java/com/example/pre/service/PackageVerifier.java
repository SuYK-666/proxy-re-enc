package com.example.pre.service;

import com.example.pre.model.ShareGrant;
import com.example.pre.model.SharedPackageV2;

import java.time.Instant;

public final class PackageVerifier {
    public void verify(SharedPackageV2 dataPackage, Instant now) {
        if (!"v2".equals(dataPackage.packageVersion())) {
            throw new ReKeyShareException(ErrorCode.PACKAGE_INVALID, "unsupported shared package version");
        }
        if (dataPackage.expiresAt() != null && !dataPackage.expiresAt().isAfter(now)) {
            throw new ReKeyShareException(ErrorCode.PACKAGE_EXPIRED, "shared package expired");
        }
        if (!dataPackage.manifest().validates(dataPackage.payload())) {
            throw new ReKeyShareException(ErrorCode.PACKAGE_INVALID, "shared package integrity validation failed");
        }
        if (!dataPackage.payload().issuedManifestHash().isBlank()
                && !dataPackage.payload().issuedManifestHash().equals(dataPackage.manifest().manifestHash())) {
            throw new ReKeyShareException(ErrorCode.PACKAGE_INVALID, "shared package differs from issued manifest");
        }
        if (dataPackage.keyVersion() != dataPackage.payload().contentKeyVersion()) {
            throw new ReKeyShareException(ErrorCode.PACKAGE_INVALID, "shared package key version mismatch");
        }
    }

    public void verifyFormalPackage(SharedPackageV2 dataPackage, ShareGrant grant,
                                    ConversionProofService trustedProofs, Instant now) {
        verify(dataPackage, now);
        if (!trustedProofs.verifyTrusted(dataPackage.payload().conversionProof(), dataPackage.payload(), grant, now)) {
            throw new ReKeyShareException(ErrorCode.PROOF_INVALID, "conversion proof validation failed");
        }
    }
}
