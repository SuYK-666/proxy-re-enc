package com.example.pre.service;

import com.example.pre.model.UserRole;

public record SecurityContext(
        String userId,
        UserRole role,
        String tenantId,
        String tokenId,
        long issuedAt,
        long expiresAt
) {
    public boolean hasRole(UserRole expected) {
        return role == expected || role == UserRole.ADMIN;
    }

    public String auditActor() {
        return userId + "@" + tenantId;
    }
}
