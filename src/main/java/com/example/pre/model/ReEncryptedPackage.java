package com.example.pre.model;

import com.example.pre.crypto.EncryptedKeyCapsule;

import java.time.Instant;

public record ReEncryptedPackage(
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
}
