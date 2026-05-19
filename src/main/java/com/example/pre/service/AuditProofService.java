package com.example.pre.service;

import com.example.pre.crypto.hash.Hash;
import com.example.pre.model.AuditEvent;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class AuditProofService {
    public record AuditProof(
            Instant generatedAt,
            int eventCount,
            String chainRoot,
            String merkleRoot,
            String signature
    ) {
    }

    private final String signingSecret;

    public AuditProofService(String signingSecret) {
        this.signingSecret = signingSecret;
    }

    public AuditProof createProof(List<AuditEvent> events) {
        AuditService.AuditVerificationResult verification = AuditService.verifyChain(events);
        String merkleRoot = merkleRoot(events.stream().map(AuditEvent::eventHash).toList());
        String message = verification.rootHash() + "|" + merkleRoot + "|" + events.size();
        String signature = sign(message);
        return new AuditProof(Instant.now(), events.size(), verification.rootHash(), merkleRoot, signature);
    }

    public boolean verifyProof(AuditProof proof) {
        String message = proof.chainRoot() + "|" + proof.merkleRoot() + "|" + proof.eventCount();
        return java.security.MessageDigest.isEqual(
                sign(message).getBytes(StandardCharsets.UTF_8),
                proof.signature().getBytes(StandardCharsets.UTF_8)
        );
    }

    public String exportJson(AuditProof proof) {
        return "{"
                + "\"generatedAt\":\"" + proof.generatedAt() + "\","
                + "\"eventCount\":" + proof.eventCount() + ","
                + "\"chainRoot\":\"" + proof.chainRoot() + "\","
                + "\"merkleRoot\":\"" + proof.merkleRoot() + "\","
                + "\"signature\":\"" + proof.signature() + "\""
                + "}";
    }

    private static String merkleRoot(List<String> hashes) {
        if (hashes.isEmpty()) {
            return "GENESIS";
        }
        List<String> level = new ArrayList<>(hashes);
        while (level.size() > 1) {
            List<String> next = new ArrayList<>();
            for (int i = 0; i < level.size(); i += 2) {
                String left = level.get(i);
                String right = i + 1 < level.size() ? level.get(i + 1) : left;
                next.add(Hash.sha256Hex((left + right).getBytes(StandardCharsets.UTF_8)));
            }
            level = next;
        }
        return level.get(0);
    }

    private String sign(String message) {
        return Hash.sha256Hex(("ReKeyShare-Audit-v1|" + signingSecret + "|" + message).getBytes(StandardCharsets.UTF_8));
    }
}
