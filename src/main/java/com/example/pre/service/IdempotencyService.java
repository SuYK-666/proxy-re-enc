package com.example.pre.service;

import com.example.pre.crypto.hash.Hash;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public final class IdempotencyService {
    public record Outcome(int status, String body) {
    }

    public record Pending(String scopedKey, String requestHash) {
    }

    public record Decision(Pending pending, Outcome replay) {
        public boolean replayed() {
            return replay != null;
        }
    }

    private record Record(String requestHash, Outcome outcome, Instant expiresAt) {
    }

    private final Map<String, Record> records = new ConcurrentHashMap<>();
    private final Duration retention;

    public IdempotencyService(Duration retention) {
        if (retention.isNegative() || retention.isZero()) {
            throw new IllegalArgumentException("idempotency retention must be positive");
        }
        this.retention = retention;
    }

    public synchronized String execute(String key, String actor, String action, String resource, String requestBody,
                                       Supplier<String> operation) {
        if (key == null || key.isBlank()) {
            return operation.get();
        }
        Decision decision = begin(key, actor, action, resource, requestBody);
        if (decision.replayed()) {
            return decision.replay().body();
        }
        String response = operation.get();
        complete(decision.pending(), 200, response);
        return response;
    }

    public synchronized Decision begin(String key, String actor, String action, String resource, String requestBody) {
        Instant now = Instant.now();
        records.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
        String scopedKey = actor + "|" + action + "|" + resource + "|" + key;
        String requestHash = Hash.sha256Hex(requestBody.getBytes(StandardCharsets.UTF_8));
        Record existing = records.get(scopedKey);
        if (existing != null) {
            if (!existing.requestHash().equals(requestHash)) {
                throw new ReKeyShareException(ErrorCode.IDEMPOTENCY_CONFLICT,
                        "idempotency key has already been used for a different request");
            }
            if (existing.outcome() == null) {
                throw new ReKeyShareException(ErrorCode.IDEMPOTENCY_CONFLICT,
                        "idempotent request is already in progress");
            }
            return new Decision(null, existing.outcome());
        }
        Pending pending = new Pending(scopedKey, requestHash);
        records.put(scopedKey, new Record(requestHash, null, now.plus(retention)));
        return new Decision(pending, null);
    }

    public synchronized void complete(Pending pending, int status, String body) {
        if (pending == null) {
            return;
        }
        Record existing = records.get(pending.scopedKey());
        if (existing != null && existing.requestHash().equals(pending.requestHash())) {
            records.put(pending.scopedKey(), new Record(existing.requestHash(), new Outcome(status, body),
                    existing.expiresAt()));
        }
    }
}
