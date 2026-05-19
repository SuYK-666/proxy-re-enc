package com.example.pre.model;

import com.example.pre.crypto.ReEncryptionKey;

import java.time.Instant;
import java.util.UUID;

public record ShareGrant(
        String grantId,
        String dataId,
        String ownerId,
        String recipientId,
        AlgorithmType algorithm,
        GrantStatus status,
        AccessPolicy policy,
        String policyHash,
        ReEncryptionKey reKey,
        int accessCount,
        int reEncryptCount,
        int downloadCount,
        int decryptCount,
        int previewCount,
        Instant createdAt,
        Instant expiresAt,
        Instant revokedAt,
        String revokeReason,
        int contentKeyVersion
) {
    public static ShareGrant active(
            String dataId,
            String ownerId,
            String recipientId,
            AlgorithmType algorithm,
            AccessPolicy policy,
            String policyHash,
            ReEncryptionKey reKey,
            int contentKeyVersion
    ) {
        return new ShareGrant(
                UUID.randomUUID().toString(),
                dataId,
                ownerId,
                recipientId,
                algorithm,
                GrantStatus.ACTIVE,
                policy,
                policyHash,
                reKey,
                0,
                0,
                0,
                0,
                0,
                Instant.now(),
                policy.expiresAt(),
                null,
                "",
                contentKeyVersion
        );
    }

    public boolean canUse(Instant now) {
        return status == GrantStatus.ACTIVE && !policy.expired(now) && accessCount < policy.maxAccessCount();
    }

    public ShareGrant incrementAccess() {
        return new ShareGrant(grantId, dataId, ownerId, recipientId, algorithm, status, policy, policyHash, reKey,
                accessCount + 1, reEncryptCount, downloadCount, decryptCount, previewCount,
                createdAt, expiresAt, revokedAt, revokeReason, contentKeyVersion);
    }

    public ShareGrant incrementReEncrypt() {
        return new ShareGrant(grantId, dataId, ownerId, recipientId, algorithm, status, policy, policyHash, reKey,
                accessCount, reEncryptCount + 1, downloadCount, decryptCount, previewCount,
                createdAt, expiresAt, revokedAt, revokeReason, contentKeyVersion);
    }

    public ShareGrant incrementDownload() {
        return new ShareGrant(grantId, dataId, ownerId, recipientId, algorithm, status, policy, policyHash, reKey,
                accessCount + 1, reEncryptCount, downloadCount + 1, decryptCount, previewCount,
                createdAt, expiresAt, revokedAt, revokeReason, contentKeyVersion);
    }

    public ShareGrant incrementDecrypt() {
        return new ShareGrant(grantId, dataId, ownerId, recipientId, algorithm, status, policy, policyHash, reKey,
                accessCount + 1, reEncryptCount, downloadCount, decryptCount + 1, previewCount,
                createdAt, expiresAt, revokedAt, revokeReason, contentKeyVersion);
    }

    public ShareGrant incrementPreview() {
        return new ShareGrant(grantId, dataId, ownerId, recipientId, algorithm, status, policy, policyHash, reKey,
                accessCount + 1, reEncryptCount, downloadCount, decryptCount, previewCount + 1,
                createdAt, expiresAt, revokedAt, revokeReason, contentKeyVersion);
    }

    public ShareGrant revoke() {
        return new ShareGrant(grantId, dataId, ownerId, recipientId, algorithm, GrantStatus.REVOKED, policy, policyHash,
                reKey, accessCount, reEncryptCount, downloadCount, decryptCount, previewCount,
                createdAt, expiresAt, Instant.now(), "manual revoke", contentKeyVersion);
    }

    public ShareGrant expire() {
        return new ShareGrant(grantId, dataId, ownerId, recipientId, algorithm, GrantStatus.EXPIRED, policy, policyHash,
                reKey, accessCount, reEncryptCount, downloadCount, decryptCount, previewCount,
                createdAt, expiresAt, revokedAt, revokeReason, contentKeyVersion);
    }

    public ShareGrant rotate() {
        return new ShareGrant(grantId, dataId, ownerId, recipientId, algorithm, GrantStatus.ROTATED, policy, policyHash,
                reKey, accessCount, reEncryptCount, downloadCount, decryptCount, previewCount,
                createdAt, expiresAt, revokedAt, "content key rotated", contentKeyVersion);
    }
}
