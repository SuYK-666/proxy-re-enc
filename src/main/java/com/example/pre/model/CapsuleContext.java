package com.example.pre.model;

public record CapsuleContext(
        String dataId,
        String ownerId,
        String recipientId,
        AlgorithmType algorithm,
        String ownerKeyId,
        int contentKeyVersion,
        String policyHash,
        String tenantId,
        String grantId,
        String algorithmSuite,
        String proofIssuerId,
        String operation
) {
    public CapsuleContext(String dataId, String ownerId, String recipientId, AlgorithmType algorithm,
                          String ownerKeyId, int contentKeyVersion, String policyHash) {
        this(dataId, ownerId, recipientId, algorithm, ownerKeyId, contentKeyVersion, policyHash,
                "tenant-default", "OWNER_UPLOAD", algorithm.name(), "", "OWNER_UPLOAD");
    }
}
