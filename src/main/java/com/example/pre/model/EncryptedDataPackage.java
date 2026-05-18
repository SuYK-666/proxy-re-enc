package com.example.pre.model;

import com.example.pre.crypto.EncryptedKeyCapsule;

import java.time.Instant;

public record EncryptedDataPackage(
        String dataId,
        String ownerId,
        AlgorithmType algorithm,
        byte[] encryptedContent,
        byte[] contentNonce,
        byte[] aad,
        EncryptedKeyCapsule originalCapsule,
        Instant createdAt
) {
}
