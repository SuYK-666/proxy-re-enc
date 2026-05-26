package com.example.pre.service;

import com.example.pre.crypto.hash.Hash;
import com.example.pre.model.ConversionProof;
import com.example.pre.model.PackageManifest;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

public final class ConversionProofService {
    private static final Duration MAX_PROOF_AGE = Duration.ofMinutes(15);
    private final KeyPair signingKeyPair;

    public ConversionProofService() {
        this.signingKeyPair = newKeyPair();
    }

    public ConversionProof issue(ReEncryptedPackage dataPackage, ShareGrant grant, String proxyId) {
        Instant issuedAt = Instant.now();
        String nonce = Base64.getEncoder().encodeToString(SecureRandomUtil.randomBytes(16));
        ConversionProof unsigned = new ConversionProof("conversion-proof-v1", dataPackage.algorithm().name(),
                objectDigest(dataPackage), grantDigest(grant), capsuleDigest(dataPackage), packageDigest(dataPackage),
                proxyId, issuedAt, nonce, "Ed25519",
                Base64.getEncoder().encodeToString(signingKeyPair.getPublic().getEncoded()), "");
        return new ConversionProof(unsigned.proofVersion(), unsigned.algorithmSuite(), unsigned.objectDigest(),
                unsigned.grantDigest(), unsigned.capsuleDigest(), unsigned.packageDigest(), unsigned.proxyId(),
                unsigned.issuedAt(), unsigned.nonce(), unsigned.signatureAlgorithm(), unsigned.publicKey(),
                sign(unsigned));
    }

    public boolean verifyTrusted(ConversionProof proof, ReEncryptedPackage dataPackage, ShareGrant grant, Instant now) {
        return proof != null
                && java.security.MessageDigest.isEqual(signingKeyPair.getPublic().getEncoded(),
                Base64.getDecoder().decode(proof.publicKey()))
                && verify(proof, dataPackage, grant, now);
    }

    public static boolean verify(ConversionProof proof, ReEncryptedPackage dataPackage, ShareGrant grant, Instant now) {
        if (proof == null || !"conversion-proof-v1".equals(proof.proofVersion())
                || !"Ed25519".equals(proof.signatureAlgorithm())
                || proof.issuedAt().isAfter(now.plusSeconds(30))
                || proof.issuedAt().plus(MAX_PROOF_AGE).isBefore(now)
                || !proof.algorithmSuite().equals(dataPackage.algorithm().name())
                || !proof.objectDigest().equals(objectDigest(dataPackage))
                || !proof.grantDigest().equals(grantDigest(grant))
                || !proof.capsuleDigest().equals(capsuleDigest(dataPackage))
                || !proof.packageDigest().equals(packageDigest(dataPackage))) {
            return false;
        }
        try {
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(proof.publicKey())));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(payload(proof).getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(proof.signature()));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    public static String digest(ConversionProof proof) {
        return Hash.sha256Hex(payload(proof) + "|" + proof.signature());
    }

    private String sign(ConversionProof proof) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(signingKeyPair.getPrivate());
            signer.update(payload(proof).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot issue conversion proof", e);
        }
    }

    private static String payload(ConversionProof proof) {
        return String.join("|", proof.proofVersion(), proof.algorithmSuite(), proof.objectDigest(),
                proof.grantDigest(), proof.capsuleDigest(), proof.packageDigest(), proof.proxyId(),
                proof.issuedAt().toString(), proof.nonce(), proof.signatureAlgorithm(), proof.publicKey());
    }

    private static String objectDigest(ReEncryptedPackage dataPackage) {
        return Hash.sha256Hex(dataPackage.encryptedContent());
    }

    private static String grantDigest(ShareGrant grant) {
        return Hash.sha256Hex(String.join("|", grant.grantId(), grant.dataId(), grant.ownerId(), grant.recipientId(),
                grant.policyHash(), Integer.toString(grant.contentKeyVersion())));
    }

    private static String capsuleDigest(ReEncryptedPackage dataPackage) {
        return Hash.sha256Hex(Bytes.concat(dataPackage.reEncryptedCapsule().header(),
                dataPackage.reEncryptedCapsule().wrappedKey(), dataPackage.reEncryptedCapsule().keyNonce()));
    }

    private static String packageDigest(ReEncryptedPackage dataPackage) {
        return PackageManifest.issue(dataPackage).manifestHash();
    }

    private static KeyPair newKeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is not available", e);
        }
    }
}
