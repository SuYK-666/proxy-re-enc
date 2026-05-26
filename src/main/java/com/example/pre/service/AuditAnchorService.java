package com.example.pre.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

public final class AuditAnchorService {
    private final AuditProofService proofService;
    private final Path anchorLog;

    public AuditAnchorService(AuditProofService proofService, Path anchorLog) {
        this.proofService = proofService;
        this.anchorLog = anchorLog;
    }

    public AuditProofService.AuditProof anchor(java.util.List<com.example.pre.model.AuditEvent> events) {
        AuditProofService.AuditProof proof = proofService.createProof(events);
        String line = Instant.now() + "|" + proof.eventCount() + "|" + proof.chainRoot()
                + "|" + proof.merkleRoot() + "|" + proof.signature() + System.lineSeparator();
        try {
            if (anchorLog.getParent() != null) {
                Files.createDirectories(anchorLog.getParent());
            }
            Files.writeString(anchorLog, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return proof;
        } catch (IOException e) {
            throw new ReKeyShareException(ErrorCode.AUDIT_CHAIN_BROKEN, "audit anchor write failed: " + e.getMessage());
        }
    }
}
