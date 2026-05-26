package com.example.pre.model;

import com.example.pre.crypto.provider.SchemeDescriptor;

import java.time.Instant;

public record SharedPackageV2(
        String packageVersion,
        String schemeId,
        String parameterSpec,
        String proofStatus,
        int keyVersion,
        Instant expiresAt,
        ReEncryptedPackage payload,
        PackageManifest manifest
) {
    public static SharedPackageV2 issue(ReEncryptedPackage dataPackage, SchemeDescriptor descriptor, Instant expiresAt) {
        return new SharedPackageV2("v2", descriptor.schemeId(), descriptor.parameterSpec(), descriptor.proofStatus(),
                dataPackage.contentKeyVersion(), expiresAt, dataPackage, PackageManifest.issue(dataPackage));
    }
}
