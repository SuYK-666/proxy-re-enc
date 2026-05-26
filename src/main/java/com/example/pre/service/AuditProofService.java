package com.example.pre.service;

import com.example.pre.model.AuditEvent;
import com.example.pre.crypto.hash.Hash;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public final class AuditProofService {
    public record AuditProof(
            Instant generatedAt,
            int eventCount,
            String chainRoot,
            String merkleRoot,
            String signatureAlgorithm,
            String publicKey,
            String signature
    ) {
    }

    private final PrivateKey signingKey;
    private final PublicKey verificationKey;

    /**
     * Compatibility constructor for local fixtures. A fresh asymmetric signing key is
     * generated; the value is deliberately not used as a shared signing secret.
     */
    public AuditProofService(String signingSecret) {
        this(generateKeyPair());
    }

    public AuditProofService() {
        this(generateKeyPair());
    }

    public AuditProofService(KeyPair keyPair) {
        this.signingKey = keyPair.getPrivate();
        this.verificationKey = keyPair.getPublic();
    }

    public AuditProof createProof(List<AuditEvent> events) {
        AuditService.AuditVerificationResult verification = AuditService.verifyChain(events);
        String merkleRoot = merkleRoot(events.stream().map(AuditEvent::eventHash).toList());
        String message = verification.rootHash() + "|" + merkleRoot + "|" + events.size();
        String signature = sign(message);
        return new AuditProof(Instant.now(), events.size(), verification.rootHash(), merkleRoot, "Ed25519",
                Base64.getEncoder().encodeToString(verificationKey.getEncoded()), signature);
    }

    public boolean verifyProof(AuditProof proof) {
        try {
            if (!"Ed25519".equals(proof.signatureAlgorithm())
                    || !java.security.MessageDigest.isEqual(
                    verificationKey.getEncoded(),
                    Base64.getDecoder().decode(proof.publicKey()))) {
                return false;
            }
            String message = proof.chainRoot() + "|" + proof.merkleRoot() + "|" + proof.eventCount();
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(verificationKey);
            verifier.update(message.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(proof.signature()));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    public String exportJson(AuditProof proof) {
        return "{"
                + "\"generatedAt\":\"" + proof.generatedAt() + "\","
                + "\"eventCount\":" + proof.eventCount() + ","
                + "\"chainRoot\":\"" + proof.chainRoot() + "\","
                + "\"merkleRoot\":\"" + proof.merkleRoot() + "\","
                + "\"signatureAlgorithm\":\"" + proof.signatureAlgorithm() + "\","
                + "\"publicKey\":\"" + proof.publicKey() + "\","
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
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(signingKey);
            signer.update(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot sign audit proof", e);
        }
    }

    private static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is not available", e);
        }
    }
}
