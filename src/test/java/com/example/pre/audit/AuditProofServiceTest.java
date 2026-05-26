package com.example.pre.audit;

import com.example.pre.model.AuditEvent;
import com.example.pre.service.AuditProofService;
import com.example.pre.storage.InMemoryAuditRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditProofServiceTest {
    @Test
    void exportsMerkleRootAndSignatureForAuditEvents() {
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        audit.record(new AuditEvent(Instant.now(), "Alice", "DATA_UPLOAD", "data-1", true, "ok"));
        audit.record(new AuditEvent(Instant.now(), "Bob", "DOWNLOAD_PACKAGE", "pkg-1", true, "ok"));

        AuditProofService service = new AuditProofService("test-secret");
        AuditProofService.AuditProof proof = service.createProof(audit.findAll());
        String json = service.exportJson(proof);

        assertEquals(2, proof.eventCount());
        assertTrue(json.contains("\"merkleRoot\""));
        assertTrue(json.contains("\"signatureAlgorithm\":\"Ed25519\""));
        assertTrue(json.contains("\"publicKey\""));
        assertTrue(json.contains("\"signature\""));
        assertTrue(service.verifyProof(proof));
    }

    @Test
    void rejectsTamperedProofAndProofFromDifferentKey() {
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        audit.record(new AuditEvent(Instant.now(), "Alice", "DATA_UPLOAD", "data-1", true, "ok"));

        AuditProofService signer = new AuditProofService();
        AuditProofService.AuditProof proof = signer.createProof(audit.findAll());
        AuditProofService.AuditProof tampered = new AuditProofService.AuditProof(
                proof.generatedAt(), proof.eventCount(), "tampered", proof.merkleRoot(),
                proof.signatureAlgorithm(), proof.publicKey(), proof.signature());

        assertFalse(signer.verifyProof(tampered));
        assertFalse(new AuditProofService().verifyProof(proof));
    }
}
