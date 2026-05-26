package com.example.pre.model;

import java.time.Instant;

public record DataObject(
        String dataId,
        String ownerId,
        String fileName,
        String contentType,
        long originalSize,
        long ciphertextSize,
        String ciphertextHash,
        AlgorithmType algorithm,
        String ownerKeyId,
        int contentKeyVersion,
        String capsuleId,
        String storagePath,
        Instant createdAt,
        Instant updatedAt
) {
    public static DataObject fromPackage(EncryptedDataPackage dataPackage) {
        return new DataObject(
                dataPackage.dataId(),
                dataPackage.ownerId(),
                dataPackage.fileName(),
                dataPackage.contentType(),
                dataPackage.originalSize(),
                dataPackage.ciphertextSize(),
                dataPackage.ciphertextHash(),
                dataPackage.algorithm(),
                dataPackage.ownerKeyId(),
                dataPackage.contentKeyVersion(),
                dataPackage.originalCapsule().capsuleId(),
                dataPackage.storagePath(),
                dataPackage.createdAt(),
                dataPackage.createdAt()
        );
    }
}
