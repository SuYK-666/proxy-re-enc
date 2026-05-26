package com.example.pre.model;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.util.Bytes;

import java.time.Instant;
import java.util.UUID;

public record EncryptedDataPackage(
        String dataId,
        String ownerId,
        AlgorithmType algorithm,
        byte[] encryptedContent,
        byte[] contentNonce,
        byte[] aad,
        EncryptedKeyCapsule originalCapsule,
        Instant createdAt,
        String fileName,
        String contentType,
        long originalSize,
        long ciphertextSize,
        String ciphertextHash,
        String ownerKeyId,
        int contentKeyVersion,
        String storagePath,
        String policyHash,
        String contextHash
) {
    public EncryptedDataPackage(
            String dataId,
            String ownerId,
            AlgorithmType algorithm,
            byte[] encryptedContent,
            byte[] contentNonce,
            byte[] aad,
            EncryptedKeyCapsule originalCapsule,
            Instant createdAt
    ) {
        this(
                dataId,
                ownerId,
                algorithm,
                encryptedContent,
                contentNonce,
                aad,
                originalCapsule,
                createdAt,
                "demo-" + dataId + ".bin",
                "application/octet-stream",
                -1,
                encryptedContent.length,
                Bytes.hex(com.example.pre.crypto.hash.Hash.sha256(encryptedContent), 32),
                "demo-key-" + ownerId,
                1,
                "memory://" + dataId + "/v1",
                "",
                ""
        );
    }

    public static EncryptedDataPackage uploadedEncrypted(
            String dataId,
            String ownerId,
            AlgorithmType algorithm,
            byte[] encryptedContent,
            byte[] contentNonce,
            byte[] aad,
            EncryptedKeyCapsule originalCapsule,
            long originalSize,
            String fileName,
            String contentType,
            String ownerKeyId,
            int contentKeyVersion,
            String policyHash,
            String contextHash
    ) {
        String storagePath = "storage/ciphertexts/" + dataId + "-v" + contentKeyVersion + ".bin";
        return new EncryptedDataPackage(
                dataId,
                ownerId,
                algorithm,
                encryptedContent,
                contentNonce,
                aad,
                originalCapsule,
                Instant.now(),
                fileName,
                contentType,
                originalSize,
                encryptedContent.length,
                Bytes.hex(com.example.pre.crypto.hash.Hash.sha256(encryptedContent), 32),
                ownerKeyId,
                contentKeyVersion,
                storagePath,
                policyHash,
                contextHash
        );
    }

    public EncryptedDataPackage withContentVersion(
            byte[] newCiphertext,
            byte[] newNonce,
            byte[] newAad,
            EncryptedKeyCapsule newCapsule,
            long newOriginalSize,
            int newContentKeyVersion,
            String newPolicyHash
    ) {
        return uploadedEncrypted(
                dataId,
                ownerId,
                algorithm,
                newCiphertext,
                newNonce,
                newAad,
                newCapsule,
                newOriginalSize,
                fileName,
                contentType,
                ownerKeyId,
                newContentKeyVersion,
                newPolicyHash,
                com.example.pre.crypto.hash.Hash.sha256Hex(newAad)
        );
    }

    public EncryptedDataPackage withOwnerSideEncryptedVersion(
            byte[] newCiphertext,
            byte[] newNonce,
            byte[] newAad,
            EncryptedKeyCapsule newCapsule,
            int newContentKeyVersion,
            String newPolicyHash,
            String newContextHash
    ) {
        String storagePath = "storage/ciphertexts/" + dataId + "-v" + newContentKeyVersion + ".bin";
        return new EncryptedDataPackage(
                dataId,
                ownerId,
                algorithm,
                newCiphertext,
                newNonce,
                newAad,
                newCapsule,
                Instant.now(),
                fileName,
                contentType,
                originalSize,
                newCiphertext.length,
                Bytes.hex(com.example.pre.crypto.hash.Hash.sha256(newCiphertext), 32),
                ownerKeyId,
                newContentKeyVersion,
                storagePath,
                newPolicyHash,
                newContextHash
        );
    }
}
