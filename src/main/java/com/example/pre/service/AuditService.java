package com.example.pre.service;

import com.example.pre.model.AuditEvent;
import com.example.pre.storage.AuditRepository;
import com.example.pre.crypto.hash.Hash;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

public final class AuditService {
    public record AuditVerificationResult(boolean valid, int checkedEvents, Integer brokenAt, String rootHash) {
    }

    private final AuditRepository audit;

    public AuditService(AuditRepository audit) {
        this.audit = audit;
    }

    public void record(String actorId, String action, String targetId, boolean success, String message) {
        audit.record(new AuditEvent(Instant.now(), actorId, action, targetId, success, message));
    }

    public List<AuditEvent> events() {
        return audit.findAll();
    }

    public AuditVerificationResult verifyChain() {
        return verifyChain(audit.findAll());
    }

    public static AuditVerificationResult verifyChain(List<AuditEvent> events) {
        String previousHash = "GENESIS";
        for (int i = 0; i < events.size(); i++) {
            AuditEvent event = events.get(i);
            String expected = Hash.sha256Hex(event.canonicalWithoutHash(previousHash));
            if (!Objects.equals(previousHash, event.previousHash()) || !Objects.equals(expected, event.eventHash())) {
                return new AuditVerificationResult(false, events.size(), i, previousHash);
            }
            previousHash = event.eventHash();
        }
        return new AuditVerificationResult(true, events.size(), null, previousHash);
    }
}
