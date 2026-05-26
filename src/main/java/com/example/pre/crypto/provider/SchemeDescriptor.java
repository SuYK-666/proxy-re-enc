package com.example.pre.crypto.provider;

public record SchemeDescriptor(
        String schemeId,
        String algorithmFamily,
        String securityLevel,
        String parameterSpec,
        boolean baselineOnly,
        boolean supportsProxyTransform,
        boolean supportsThreshold,
        String proofStatus,
        String implementationStatus
) {
    public boolean allowedAsProductionDefault() {
        return !baselineOnly && "IMPLEMENTED".equals(implementationStatus);
    }
}
