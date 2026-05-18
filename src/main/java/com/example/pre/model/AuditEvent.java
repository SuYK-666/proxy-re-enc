package com.example.pre.model;

import java.time.Instant;

public record AuditEvent(
        Instant timestamp,
        String actor,
        String action,
        String target,
        boolean success,
        String message
) {
}
