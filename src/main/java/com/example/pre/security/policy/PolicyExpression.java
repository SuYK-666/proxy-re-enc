package com.example.pre.security.policy;

import java.time.Instant;
import java.util.Set;

public record PolicyExpression(
        String tenantId,
        Set<String> allowedRoles,
        Set<String> allowedActions,
        String requiredPurpose,
        String requiredClassification,
        Instant notBefore,
        Instant expiresAt,
        int maxAccessCount,
        boolean requireActiveProxy
) {
    public PolicyExpression {
        tenantId = tenantId == null ? "" : tenantId;
        allowedRoles = allowedRoles == null ? Set.of() : Set.copyOf(allowedRoles);
        allowedActions = allowedActions == null ? Set.of() : Set.copyOf(allowedActions);
        requiredPurpose = requiredPurpose == null ? "" : requiredPurpose;
        requiredClassification = requiredClassification == null ? "" : requiredClassification;
        if (maxAccessCount < 1) {
            throw new IllegalArgumentException("maxAccessCount must be positive");
        }
    }

    public String canonical() {
        return String.join("|", tenantId, allowedRoles.stream().sorted().toList().toString(),
                allowedActions.stream().sorted().toList().toString(), requiredPurpose,
                requiredClassification, String.valueOf(notBefore), String.valueOf(expiresAt),
                Integer.toString(maxAccessCount), Boolean.toString(requireActiveProxy));
    }
}
