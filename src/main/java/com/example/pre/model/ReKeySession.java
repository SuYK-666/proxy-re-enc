package com.example.pre.model;

import com.example.pre.crypto.ecc.ReKeySessionContext;

import java.time.Instant;
import java.util.UUID;

public record ReKeySession(
        String sessionId,
        String dataId,
        String ownerId,
        String recipientId,
        AlgorithmType algorithm,
        String challenge,
        String status,
        Instant createdAt,
        Instant expiresAt
) {
    public static ReKeySession create(String dataId, String ownerId, String recipientId, AlgorithmType algorithm, Instant expiresAt) {
        return new ReKeySession(UUID.randomUUID().toString(), dataId, ownerId, recipientId, algorithm,
                UUID.randomUUID().toString(), "CREATED", Instant.now(), expiresAt);
    }

    public boolean expired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    public ReKeySession completed() {
        return new ReKeySession(sessionId, dataId, ownerId, recipientId, algorithm, challenge, "COMPLETED", createdAt, expiresAt);
    }

    public ReKeySession shareSubmitted() {
        return new ReKeySession(sessionId, dataId, ownerId, recipientId, algorithm, challenge, "SHARE_SUBMITTED", createdAt, expiresAt);
    }

    public ReKeySessionContext cryptoContext() {
        return new ReKeySessionContext(challenge, createdAt);
    }
}
