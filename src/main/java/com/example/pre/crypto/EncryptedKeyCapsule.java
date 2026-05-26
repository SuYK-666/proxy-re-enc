package com.example.pre.crypto;

import com.example.pre.model.AlgorithmType;

import java.time.Instant;
import java.util.UUID;

public record EncryptedKeyCapsule(
        String capsuleId,
        AlgorithmType algorithm,
        String parameterSpec,
        String ownerKeyId,
        int ownerKeyVersion,
        byte[] header,
        byte[] wrappedKey,
        byte[] keyNonce,
        String aadHash,
        String contextHash,
        Instant createdAt
) {
    public EncryptedKeyCapsule(
            AlgorithmType algorithm,
            byte[] header,
            byte[] wrappedKey,
            byte[] keyNonce
    ) {
        this(
                UUID.randomUUID().toString(),
                algorithm,
                algorithm.name() + "-teaching-prototype",
                "",
                1,
                header,
                wrappedKey,
                keyNonce,
                "",
                "",
                Instant.now()
        );
    }

    public EncryptedKeyCapsule bindContext(String ownerKeyId, int ownerKeyVersion, String aadHash, String contextHash, String parameterSpec) {
        return new EncryptedKeyCapsule(
                capsuleId,
                algorithm,
                parameterSpec,
                ownerKeyId,
                ownerKeyVersion,
                header,
                wrappedKey,
                keyNonce,
                aadHash,
                contextHash,
                createdAt
        );
    }
}
