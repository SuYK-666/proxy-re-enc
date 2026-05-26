package com.example.pre.security.policy;

import java.time.Instant;

public record PolicyRequest(
        String subjectId,
        String role,
        String tenantId,
        String dataId,
        String classification,
        String action,
        String purpose,
        int consumedAccessCount,
        boolean proxyActive,
        Instant now
) {
}
