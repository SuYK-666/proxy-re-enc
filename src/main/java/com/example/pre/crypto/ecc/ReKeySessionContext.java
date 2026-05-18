package com.example.pre.crypto.ecc;

import java.time.Instant;
import java.util.UUID;

public record ReKeySessionContext(String sessionId, Instant createdAt) {
    public static ReKeySessionContext create() {
        return new ReKeySessionContext(UUID.randomUUID().toString(), Instant.now());
    }
}
