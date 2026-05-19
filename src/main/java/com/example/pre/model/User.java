package com.example.pre.model;

import java.time.Instant;

public record User(
        String userId,
        UserKeyPair keyPair,
        String username,
        UserRole role,
        UserStatus status,
        Instant createdAt
) {
    public User(String userId, UserKeyPair keyPair) {
        this(userId, keyPair, userId, UserRole.RECIPIENT, UserStatus.ACTIVE, Instant.now());
    }

    public User withRole(UserRole newRole) {
        return new User(userId, keyPair, username, newRole, status, createdAt);
    }
}
