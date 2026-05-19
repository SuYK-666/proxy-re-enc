package com.example.pre.audit;

import com.example.pre.model.AuditEvent;
import com.example.pre.storage.InMemoryAuditRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditHashChainTest {
    @Test
    void verifiesNormalChainAndDetectsTamperedAction() {
        InMemoryAuditRepository audit = sampleChain();
        assertTrue(audit.verifyChain().valid());
        audit.replaceForDemo(2, audit.findAll().get(2).withAction("TAMPERED"));
        assertFalse(audit.verifyChain().valid());
        assertEquals(2, audit.verifyChain().brokenAt());
    }

    @Test
    void detectsMissingPreviousHashOrInsertedEvent() {
        InMemoryAuditRepository audit = sampleChain();
        AuditEvent broken = audit.findAll().get(1).withHash("wrong-previous", "wrong-hash");
        audit.replaceForDemo(1, broken);
        assertFalse(audit.verifyChain().valid());
        assertEquals(1, audit.verifyChain().brokenAt());
    }

    @Test
    void recordsEnoughEventsForEvidenceChain() {
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        for (int i = 0; i < 22; i++) {
            audit.record(new AuditEvent(Instant.now(), "actor", "EVENT_" + i, "target", true, "detail"));
        }
        assertTrue(audit.verifyChain().valid());
        assertEquals(22, audit.verifyChain().checkedEvents());
    }

    private static InMemoryAuditRepository sampleChain() {
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        audit.record(new AuditEvent(Instant.now(), "Alice", "USER_REGISTER", "Alice", true, ""));
        audit.record(new AuditEvent(Instant.now(), "Alice", "DATA_UPLOAD", "data-1", true, ""));
        audit.record(new AuditEvent(Instant.now(), "Alice", "GRANT_CREATE", "grant-1", true, ""));
        audit.record(new AuditEvent(Instant.now(), "proxy", "PROXY_REENCRYPT", "package-1", true, ""));
        return audit;
    }
}
