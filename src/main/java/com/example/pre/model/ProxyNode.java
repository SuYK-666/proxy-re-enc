package com.example.pre.model;

import java.time.Instant;
import java.util.Set;

public record ProxyNode(
        String proxyId,
        String certificateFingerprint,
        ProxyNodeStatus status,
        Set<String> allowedTenantIds,
        Instant createdAt,
        Instant revokedAt,
        Instant lastSeenAt
) {
    public static ProxyNode active(String proxyId, String certificateFingerprint, Set<String> allowedTenantIds) {
        return new ProxyNode(proxyId, certificateFingerprint, ProxyNodeStatus.ACTIVE,
                Set.copyOf(allowedTenantIds), Instant.now(), null, Instant.now());
    }

    public ProxyNode revoke() {
        return new ProxyNode(proxyId, certificateFingerprint, ProxyNodeStatus.REVOKED,
                allowedTenantIds, createdAt, Instant.now(), lastSeenAt);
    }

    public ProxyNode seen() {
        return new ProxyNode(proxyId, certificateFingerprint, status, allowedTenantIds, createdAt, revokedAt, Instant.now());
    }
}
