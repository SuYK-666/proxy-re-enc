package com.example.pre.storage;

import com.example.pre.crypto.hash.Hash;
import com.example.pre.model.AuditEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class InMemoryAuditRepository implements AuditRepository {
    public record VerificationResult(boolean valid, int checkedEvents, int brokenAt, String rootHash) {
    }

    private static final String GENESIS_HASH = "GENESIS";
    private final List<AuditEvent> events = new ArrayList<>();

    @Override
    public synchronized void record(AuditEvent event) {
        String previousHash = events.isEmpty() ? GENESIS_HASH : events.get(events.size() - 1).eventHash();
        String eventHash = Hash.sha256Hex(event.canonicalWithoutHash(previousHash));
        events.add(event.withHash(previousHash, eventHash));
    }

    @Override
    public synchronized List<AuditEvent> findAll() {
        return List.copyOf(events);
    }

    public synchronized VerificationResult verifyChain() {
        String previousHash = GENESIS_HASH;
        for (int i = 0; i < events.size(); i++) {
            AuditEvent event = events.get(i);
            String expected = Hash.sha256Hex(event.canonicalWithoutHash(previousHash));
            if (!Objects.equals(previousHash, event.previousHash()) || !Objects.equals(expected, event.eventHash())) {
                return new VerificationResult(false, events.size(), i, previousHash);
            }
            previousHash = event.eventHash();
        }
        return new VerificationResult(true, events.size(), -1, previousHash);
    }

    public synchronized void replaceForDemo(int index, AuditEvent event) {
        events.set(index, event);
    }
}
