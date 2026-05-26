package com.example.pre.app;

import com.example.pre.crypto.provider.SecureEnvelopeProvider;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.CapsuleContext;
import com.example.pre.service.AuditProofService;
import com.example.pre.service.AuditService;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.util.SecureRandomUtil;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

public final class VerificationCli {
    private VerificationCli() {
    }

    public static void main(String[] args) throws Exception {
        int status = run(args, System.out);
        if (status != 0) {
            System.exit(status);
        }
    }

    public static int run(String[] args, PrintStream out) throws Exception {
        String command = String.join(" ", args);
        return switch (command) {
            case "crypto verify-envelope" -> verifyEnvelope(out);
            case "audit verify" -> verifyAudit(out);
            case "attack-matrix check" -> verifyAttackMatrix(out);
            default -> {
                out.println("{\"valid\":false,\"errorCode\":\"INVALID_REQUEST\","
                        + "\"usage\":\"crypto verify-envelope | audit verify | attack-matrix check\"}");
                yield 2;
            }
        };
    }

    private static int verifyEnvelope(PrintStream out) {
        SecureEnvelopeProvider provider = new SecureEnvelopeProvider();
        var recipient = provider.generateKeyPair("recipient");
        byte[] dek = SecureRandomUtil.randomBytes(32);
        CapsuleContext context = new CapsuleContext("cli-object", "owner", "recipient",
                AlgorithmType.SECURE_ENVELOPE, "owner-key-v1", 1, "cli-policy",
                "tenant-cli", "grant-cli", "SECURE_ENVELOPE_V1", "proxy-cli", "VERIFY_ENVELOPE");
        var capsule = provider.encapsulate(dek, recipient.publicKey(), context);
        boolean recovered = java.util.Arrays.equals(dek, provider.decapsulate(capsule, recipient.privateKey(), context));
        boolean tamperRejected = false;
        try {
            CapsuleContext altered = new CapsuleContext("other-object", "owner", "recipient",
                    AlgorithmType.SECURE_ENVELOPE, "owner-key-v1", 1, "cli-policy",
                    "tenant-cli", "grant-cli", "SECURE_ENVELOPE_V1", "proxy-cli", "VERIFY_ENVELOPE");
            provider.decapsulate(capsule, recipient.privateKey(), altered);
        } catch (IllegalArgumentException expected) {
            tamperRejected = true;
        }
        boolean valid = recovered && tamperRejected;
        out.println("{\"command\":\"crypto verify-envelope\",\"valid\":" + valid
                + ",\"contextTamperRejected\":" + tamperRejected + "}");
        return valid ? 0 : 1;
    }

    private static int verifyAudit(PrintStream out) {
        InMemoryAuditRepository repository = new InMemoryAuditRepository();
        repository.record(new AuditEvent(Instant.now(), "owner", "UPLOAD", "object-1", true, "cli"));
        repository.record(new AuditEvent(Instant.now(), "proxy", "TRANSFORM", "object-1", true, "cli"));
        AuditProofService proofService = new AuditProofService();
        var proof = proofService.createProof(repository.findAll());
        boolean chainValid = new AuditService(repository).verifyChain().valid();
        boolean proofValid = proofService.verifyProof(proof);
        boolean valid = chainValid && proofValid;
        out.println("{\"command\":\"audit verify\",\"valid\":" + valid
                + ",\"chainValid\":" + chainValid + ",\"signatureValid\":" + proofValid + "}");
        return valid ? 0 : 1;
    }

    private static int verifyAttackMatrix(PrintStream out) throws Exception {
        Path matrix = Path.of("docs", "security", "attack-test-matrix.md");
        long scenarios;
        try (var lines = Files.lines(matrix)) {
            scenarios = lines.filter(line -> line.startsWith("| AT-")).count();
        }
        boolean valid = scenarios >= 30;
        out.println("{\"command\":\"attack-matrix check\",\"valid\":" + valid
                + ",\"scenarioCount\":" + scenarios + "}");
        return valid ? 0 : 1;
    }
}
