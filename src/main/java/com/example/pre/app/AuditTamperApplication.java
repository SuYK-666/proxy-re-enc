package com.example.pre.app;

import com.example.pre.crypto.hash.Hash;
import com.example.pre.model.AuditEvent;
import com.example.pre.service.AuditProofService;
import com.example.pre.service.AuditService;
import com.example.pre.storage.InMemoryAuditRepository;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class AuditTamperApplication {
    private AuditTamperApplication() {
    }

    public static void main(String[] args) {
        InMemoryAuditRepository repo = new InMemoryAuditRepository();
        AuditService audit = new AuditService(repo);
        audit.record("alice", "DATA_UPLOAD", "data-1", true, "ok");
        audit.record("alice", "GRANT_CREATE", "grant-1", true, "ok");
        audit.record("proxy", "PROXY_REENCRYPT", "pkg-1", true, "ok");

        List<AuditEvent> original = audit.events();
        AuditProofService proofService = new AuditProofService("audit-test-secret");
        AuditProofService.AuditProof originalProof = proofService.createProof(original);

        List<AuditEvent> fieldTamper = new ArrayList<>(original);
        fieldTamper.set(1, fieldTamper.get(1).withAction("TAMPERED"));

        List<AuditEvent> deleteTamper = new ArrayList<>(original);
        deleteTamper.remove(1);

        List<AuditEvent> reorderTamper = new ArrayList<>(original);
        AuditEvent tmp = reorderTamper.get(0);
        reorderTamper.set(0, reorderTamper.get(1));
        reorderTamper.set(1, tmp);

        List<AuditEvent> rewritten = rewriteWholeChain(fieldTamper);
        AuditProofService.AuditProof rewrittenProof = proofService.createProof(rewritten);

        System.out.println("{");
        System.out.println("  \"audit-normal\":\"" + pass(AuditService.verifyChain(original).valid()) + "\",");
        System.out.println("  \"audit-field-tamper\":\"" + pass(!AuditService.verifyChain(fieldTamper).valid()) + "\",");
        System.out.println("  \"audit-delete-event\":\"" + pass(!AuditService.verifyChain(deleteTamper).valid()) + "\",");
        System.out.println("  \"audit-reorder-event\":\"" + pass(!AuditService.verifyChain(reorderTamper).valid()) + "\",");
        System.out.println("  \"audit-rewrite-without-original-signature\":\""
                + pass(!originalProof.chainRoot().equals(rewrittenProof.chainRoot())) + "\",");
        System.out.println("  \"audit-checkpoint-verify\":\"" + pass(proofService.verifyProof(originalProof)) + "\"");
        System.out.println("}");
    }

    private static List<AuditEvent> rewriteWholeChain(List<AuditEvent> events) {
        List<AuditEvent> rewritten = new ArrayList<>();
        String previousHash = "GENESIS";
        for (AuditEvent event : events) {
            String hash = Hash.sha256Hex(event.canonicalWithoutHash(previousHash).getBytes(StandardCharsets.UTF_8));
            AuditEvent withHash = event.withHash(previousHash, hash);
            rewritten.add(withHash);
            previousHash = hash;
        }
        return rewritten;
    }

    private static String pass(boolean passed) {
        return passed ? "PASS" : "FAIL";
    }
}
