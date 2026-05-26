package com.example.pre.model;

import com.example.pre.crypto.EncryptedKeyCapsule;

import java.time.Instant;
import java.util.UUID;

public record ReEncryptedPackage(
        String packageId,
        String grantId,
        String dataId,
        String ownerId,
        String recipientId,
        AlgorithmType algorithm,
        byte[] encryptedContent,
        byte[] contentNonce,
        byte[] aad,
        EncryptedKeyCapsule reEncryptedCapsule,
        Instant authorizedAt,
        int contentKeyVersion,
        String ciphertextStoragePath,
        String ownerKeyId,
        String policyHash,
        String grantPolicyHash,
        String ownerContextHash,
        String grantContextHash,
        byte[] grantAad,
        PackageStatus status,
        Instant invalidatedAt,
        String invalidatedReason,
        String issuedManifestHash
) {
    public ReEncryptedPackage(
            String dataId,
            String ownerId,
            String recipientId,
            AlgorithmType algorithm,
            byte[] encryptedContent,
            byte[] contentNonce,
            byte[] aad,
            EncryptedKeyCapsule reEncryptedCapsule,
            Instant authorizedAt
    ) {
        this(
                UUID.randomUUID().toString(),
                "legacy-direct-authorize",
                dataId,
                ownerId,
                recipientId,
                algorithm,
                encryptedContent,
                contentNonce,
                aad,
                reEncryptedCapsule,
                authorizedAt,
                1,
                "memory://" + dataId + "/v1",
                "demo-key-" + ownerId,
                "OWNER_UPLOAD",
                "",
                "",
                "",
                new byte[0],
                PackageStatus.ACTIVE,
                null,
                "",
                ""
        );
    }

    public ReEncryptedPackage invalidate(PackageStatus newStatus, String reason) {
        return new ReEncryptedPackage(packageId, grantId, dataId, ownerId, recipientId, algorithm, encryptedContent,
                contentNonce, aad, reEncryptedCapsule, authorizedAt, contentKeyVersion, ciphertextStoragePath,
                ownerKeyId, policyHash, grantPolicyHash, ownerContextHash, grantContextHash, grantAad, newStatus,
                Instant.now(), reason, issuedManifestHash);
    }

    public ReEncryptedPackage withIssuedManifestHash(String hash) {
        return new ReEncryptedPackage(packageId, grantId, dataId, ownerId, recipientId, algorithm, encryptedContent,
                contentNonce, aad, reEncryptedCapsule, authorizedAt, contentKeyVersion, ciphertextStoragePath,
                ownerKeyId, policyHash, grantPolicyHash, ownerContextHash, grantContextHash, grantAad, status,
                invalidatedAt, invalidatedReason, hash);
    }
}
