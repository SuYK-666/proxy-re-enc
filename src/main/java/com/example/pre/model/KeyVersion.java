package com.example.pre.model;

import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.hash.Hash;

import java.time.Instant;
import java.util.UUID;

public record KeyVersion(
        String keyId,
        String userId,
        AlgorithmType algorithm,
        int version,
        KeyPurpose keyPurpose,
        PublicKeyMaterial publicKey,
        String fingerprint,
        KeyStatus status,
        Instant createdAt,
        Instant activatedAt,
        Instant expiresAt,
        Instant rotatedAt,
        Instant revokedAt,
        String revokeReason
) {
    public static KeyVersion active(String userId, AlgorithmType algorithm, int version, PublicKeyMaterial publicKey) {
        Instant now = Instant.now();
        return new KeyVersion(UUID.randomUUID().toString(), userId, algorithm, version, KeyPurpose.PRE_ENCAPSULATION,
                publicKey, Hash.sha256Hex(publicKey.encoded()), KeyStatus.ACTIVE, now, now, null, null, null, "");
    }

    public KeyVersion withStatus(KeyStatus newStatus) {
        Instant now = Instant.now();
        Instant newRotatedAt = newStatus == KeyStatus.ROTATED ? now : rotatedAt;
        Instant newRevokedAt = newStatus == KeyStatus.REVOKED || newStatus == KeyStatus.COMPROMISED ? now : revokedAt;
        return new KeyVersion(keyId, userId, algorithm, version, keyPurpose, publicKey, fingerprint, newStatus,
                createdAt, activatedAt, expiresAt, newRotatedAt, newRevokedAt, revokeReason);
    }

    public KeyVersion revoke(String reason) {
        return new KeyVersion(keyId, userId, algorithm, version, keyPurpose, publicKey, fingerprint, KeyStatus.REVOKED,
                createdAt, activatedAt, expiresAt, rotatedAt, Instant.now(), reason);
    }
}
