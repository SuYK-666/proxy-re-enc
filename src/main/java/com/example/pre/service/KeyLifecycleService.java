package com.example.pre.service;

import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.GrantStatus;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.GrantRepository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Coordinates revoke/rotation operations while leaving encryption and DEK
 * generation at the owner client boundary.
 */
public final class KeyLifecycleService {
    public enum RevocationMode {
        SOFT_REVOKE,
        HARD_REVOKE,
        EMERGENCY_REVOKE
    }

    public record RotationResult(RevocationMode mode, int revokedGrants, int newContentKeyVersion) {
    }

    private final RevocationService revocation;
    private final GrantRepository grants;
    private final AuditRepository audit;

    public KeyLifecycleService(RevocationService revocation, GrantRepository grants, AuditRepository audit) {
        this.revocation = revocation;
        this.grants = grants;
        this.audit = audit;
    }

    public ShareGrant softRevoke(String ownerId, String grantId, String reason) {
        ShareGrant revoked = revocation.revokeGrant(ownerId, grantId, reason);
        audit.record(new com.example.pre.model.AuditEvent(Instant.now(), ownerId, "SOFT_REVOKE_EFFECTIVE",
                grantId, true, "new transformations and package downloads blocked"));
        return revoked;
    }

    public RotationResult hardRevoke(User owner, String grantId, String reason, EncryptedDataPackage ownerPreparedRotation) {
        revocation.revokeGrant(owner.userId(), grantId, reason);
        EncryptedDataPackage rotated = revocation.acceptOwnerSideRotation(owner, ownerPreparedRotation);
        audit.record(new com.example.pre.model.AuditEvent(Instant.now(), owner.userId(), "HARD_REVOKE_EFFECTIVE",
                grantId, true, "contentKeyVersion=" + rotated.contentKeyVersion()));
        return new RotationResult(RevocationMode.HARD_REVOKE, 1, rotated.contentKeyVersion());
    }

    public RotationResult emergencyRevoke(User owner, String dataId, String reason,
                                          EncryptedDataPackage ownerPreparedRotation) {
        List<ShareGrant> active = new ArrayList<>();
        for (ShareGrant grant : grants.findByDataId(dataId)) {
            if (grant.status() == GrantStatus.ACTIVE) {
                active.add(grant);
            }
        }
        for (ShareGrant grant : active) {
            revocation.revokeGrant(owner.userId(), grant.grantId(), reason);
        }
        EncryptedDataPackage rotated = revocation.acceptOwnerSideRotation(owner, ownerPreparedRotation);
        audit.record(new com.example.pre.model.AuditEvent(Instant.now(), owner.userId(), "EMERGENCY_REVOKE_EFFECTIVE",
                dataId, true, "revoked=" + active.size() + ";contentKeyVersion=" + rotated.contentKeyVersion()));
        return new RotationResult(RevocationMode.EMERGENCY_REVOKE, active.size(), rotated.contentKeyVersion());
    }
}
