package com.example.pre.model;

public record CapsuleContext(
        String dataId,
        String ownerId,
        String recipientId,
        AlgorithmType algorithm,
        String ownerKeyId,
        int contentKeyVersion,
        String policyHash
) {
}
