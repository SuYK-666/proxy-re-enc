package com.example.pre.model;

import java.time.Instant;
import java.util.Set;

public record ProxyNode(
        String proxyId,
        String certificateFingerprint,
        ProxyNodeStatus status,
        Set<String> allowedTenantIds,
        Set<AlgorithmType> allowedSchemeIds,
        long quota,
        long usageCount,
        String suspendedReason,
        Instant createdAt,
        Instant revokedAt,
        Instant lastSeenAt
) {
    public static ProxyNode active(String proxyId, String certificateFingerprint, Set<String> allowedTenantIds) {
        return active(proxyId, certificateFingerprint, allowedTenantIds, Set.of(AlgorithmType.values()), Long.MAX_VALUE);
    }

    public static ProxyNode active(String proxyId, String certificateFingerprint, Set<String> allowedTenantIds,
                                   Set<AlgorithmType> allowedSchemeIds, long quota) {
        if (quota < 1) {
            throw new IllegalArgumentException("proxy quota must be positive");
        }
        return new ProxyNode(proxyId, certificateFingerprint, ProxyNodeStatus.ACTIVE,
                Set.copyOf(allowedTenantIds), Set.copyOf(allowedSchemeIds), quota, 0, "",
                Instant.now(), null, Instant.now());
    }

    public ProxyNode revoke() {
        return new ProxyNode(proxyId, certificateFingerprint, ProxyNodeStatus.REVOKED,
                allowedTenantIds, allowedSchemeIds, quota, usageCount, "revoked", createdAt, Instant.now(), lastSeenAt);
    }

    public ProxyNode seen() {
        return new ProxyNode(proxyId, certificateFingerprint, status, allowedTenantIds, allowedSchemeIds,
                quota, usageCount, suspendedReason, createdAt, revokedAt, Instant.now());
    }

    public ProxyNode recordUse() {
        return new ProxyNode(proxyId, certificateFingerprint, status, allowedTenantIds, allowedSchemeIds,
                quota, usageCount + 1, suspendedReason, createdAt, revokedAt, Instant.now());
    }

    public ProxyNode suspend(String reason) {
        return new ProxyNode(proxyId, certificateFingerprint, ProxyNodeStatus.DISABLED, allowedTenantIds,
                allowedSchemeIds, quota, usageCount, reason, createdAt, revokedAt, lastSeenAt);
    }
}
