package com.example.pre.service;

import com.example.pre.model.GrantStatus;
import com.example.pre.model.GrantAction;
import com.example.pre.model.PackageStatus;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.UserRole;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.DataRepository;
import com.example.pre.storage.GrantRepository;
import com.example.pre.storage.ReEncryptedPackageRepository;
import com.example.pre.util.AadBuilder;

import java.time.Instant;

public final class ObjectAuthorizationService {
    private final DataRepository dataRepository;
    private final GrantRepository grantRepository;
    private final ReEncryptedPackageRepository packageRepository;
    private final AuditRepository audit;

    public ObjectAuthorizationService(
            DataRepository dataRepository,
            GrantRepository grantRepository,
            ReEncryptedPackageRepository packageRepository,
            AuditRepository audit
    ) {
        this.dataRepository = dataRepository;
        this.grantRepository = grantRepository;
        this.packageRepository = packageRepository;
        this.audit = audit;
    }

    public void assertCanReadData(String userId, String dataId) {
        var data = dataRepository.findById(dataId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.DATA_NOT_FOUND, "data not found"));
        if (data.ownerId().equals(userId)) {
            return;
        }
        boolean allowed = grantRepository.findByDataId(dataId).stream()
                .anyMatch(grant -> grant.recipientId().equals(userId) && grant.canUse(Instant.now()));
        if (!allowed) {
            deny(userId, "UNAUTHORIZED_ACCESS", dataId, ErrorCode.ACCESS_DENIED, "user cannot read data");
        }
    }

    public void assertCanCreateGrant(String userId, String dataId) {
        var data = dataRepository.findById(dataId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.DATA_NOT_FOUND, "data not found"));
        if (!data.ownerId().equals(userId)) {
            deny(userId, "UNAUTHORIZED_ACCESS", dataId, ErrorCode.ACCESS_DENIED, "only owner can create grant");
        }
    }

    public ShareGrant assertCanUseGrant(String userId, String grantId) {
        return assertCanUseGrant(userId, grantId, GrantAction.DOWNLOAD);
    }

    public ShareGrant assertCanUseGrant(String userId, String grantId, GrantAction action) {
        ShareGrant grant = grantRepository.findById(grantId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.GRANT_NOT_FOUND, "grant not found"));
        if (!grant.recipientId().equals(userId)) {
            deny(userId, "UNAUTHORIZED_ACCESS", grantId, ErrorCode.ACCESS_DENIED, "only recipient can use grant");
        }
        validateGrantForRecipientAccess(userId, grant);
        validateActionPolicy(userId, grant, action);
        return grant;
    }

    public ShareGrant assertCanReEncryptGrant(SecurityContext proxyActor, String grantId) {
        assertProxyRole(proxyActor);
        ShareGrant grant = grantRepository.findById(grantId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.GRANT_NOT_FOUND, "grant not found"));
        validateGrantState(proxyActor.userId(), grant);
        if (grant.reEncryptCount() >= grant.policy().maxReEncryptCount()) {
            deny(proxyActor.userId(), "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.POLICY_VIOLATION, "re-encrypt count exhausted");
        }
        return grant;
    }

    public ShareGrant assertCanRevokeGrant(String userId, String grantId) {
        ShareGrant grant = grantRepository.findById(grantId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.GRANT_NOT_FOUND, "grant not found"));
        if (!grant.ownerId().equals(userId)) {
            deny(userId, "UNAUTHORIZED_ACCESS", grantId, ErrorCode.ACCESS_DENIED, "only owner can revoke grant");
        }
        return grant;
    }

    public ReEncryptedPackage assertCanDownloadPackage(String userId, String packageId) {
        ReEncryptedPackage dataPackage = assertCanAccessPackage(userId, packageId);
        ShareGrant grant = grantForPackage(dataPackage);
        validateActionPolicy(userId, grant, GrantAction.DOWNLOAD);
        assertCanRecordDownload(userId, grant);
        return dataPackage;
    }

    public ReEncryptedPackage assertCanDecryptPackage(String userId, String packageId) {
        ReEncryptedPackage dataPackage = assertCanAccessPackage(userId, packageId);
        ShareGrant grant = grantForPackage(dataPackage);
        validateActionPolicy(userId, grant, GrantAction.DECRYPT_DEMO);
        assertCanRecordDecrypt(userId, grant);
        return dataPackage;
    }

    public ReEncryptedPackage assertCanPreviewPackage(String userId, String packageId) {
        ReEncryptedPackage dataPackage = assertCanAccessPackage(userId, packageId);
        ShareGrant grant = grantForPackage(dataPackage);
        validateActionPolicy(userId, grant, GrantAction.PREVIEW);
        return dataPackage;
    }

    public void assertProxyRole(SecurityContext actor) {
        if (actor == null || !actor.hasRole(UserRole.PROXY)) {
            deny(actor == null ? "unknown" : actor.userId(), "UNAUTHORIZED_ACCESS",
                    actor == null ? "unknown" : actor.userId(), ErrorCode.ACCESS_DENIED, "only proxy role can re-encrypt");
        }
    }

    private void validateGrantState(String actorId, ShareGrant grant) {
        if (grant.status() == GrantStatus.REVOKED) {
            deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.GRANT_REVOKED, "grant revoked");
        }
        if (grant.status() == GrantStatus.ROTATED) {
            deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.KEY_REVOKED, "grant points to rotated content key");
        }
        if (grant.policy().expired(Instant.now()) || grant.status() == GrantStatus.EXPIRED) {
            deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.GRANT_EXPIRED, "grant expired");
        }
    }

    private void validateGrantForRecipientAccess(String actorId, ShareGrant grant) {
        validateGrantState(actorId, grant);
        if (grant.accessCount() >= grant.policy().maxAccessCount()) {
            deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.POLICY_VIOLATION, "access count exhausted");
        }
    }

    public void assertCanRecordDownload(String actorId, ShareGrant grant) {
        if (grant.downloadCount() >= grant.policy().maxDownloadCount()) {
            deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.POLICY_VIOLATION, "download count exhausted");
        }
    }

    public void assertCanRecordDecrypt(String actorId, ShareGrant grant) {
        if (grant.decryptCount() >= grant.policy().maxDecryptCount()) {
            deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.POLICY_VIOLATION, "decrypt count exhausted");
        }
    }

    private void validateActionPolicy(String actorId, ShareGrant grant, GrantAction action) {
        switch (action) {
            case DOWNLOAD -> {
                if (!grant.policy().allowDownload()) {
                    deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.POLICY_VIOLATION, "download is disabled");
                }
            }
            case PREVIEW -> {
                if (!grant.policy().allowPreview()) {
                    deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.POLICY_VIOLATION, "preview is disabled");
                }
            }
            case RESHARE -> {
                if (!grant.policy().allowReshare()) {
                    deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.POLICY_VIOLATION, "reshare is disabled");
                }
            }
            case DECRYPT_DEMO -> {
                if (!hasAllowedAction(grant.policy().allowedActions(), "decrypt")) {
                    deny(actorId, "GRANT_ACCESS_DENIED", grant.grantId(), ErrorCode.POLICY_VIOLATION, "decrypt is disabled");
                }
            }
            case PROXY_REENCRYPT, VIEW_AUDIT -> {
            }
            default -> throw new ReKeyShareException(ErrorCode.POLICY_VIOLATION, "unsupported grant action");
        }
    }

    private static boolean hasAllowedAction(String allowedActions, String expected) {
        for (String action : allowedActions.split(",")) {
            if (expected.equalsIgnoreCase(action.trim())) {
                return true;
            }
        }
        return false;
    }

    private ReEncryptedPackage assertCanAccessPackage(String userId, String packageId) {
        ReEncryptedPackage dataPackage = packageRepository.findById(packageId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.PACKAGE_NOT_FOUND, "package not found"));
        if (dataPackage.status() != PackageStatus.ACTIVE) {
            deny(userId, "GRANT_ACCESS_DENIED", packageId, ErrorCode.GRANT_ROTATED, "shared package is invalidated");
        }
        if (!dataPackage.recipientId().equals(userId)) {
            deny(userId, "UNAUTHORIZED_ACCESS", packageId, ErrorCode.ACCESS_DENIED, "only recipient can access package");
        }
        ShareGrant grant = grantForPackage(dataPackage);
        validateGrantForRecipientAccess(userId, grant);
        validateGrantContext(userId, dataPackage, grant);
        return dataPackage;
    }

    private void validateGrantContext(String actorId, ReEncryptedPackage dataPackage, ShareGrant grant) {
        var data = dataRepository.findById(dataPackage.dataId())
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.DATA_NOT_FOUND, "data not found"));
        if (!grant.policyHash().equals(dataPackage.grantPolicyHash())) {
            deny(actorId, "GRANT_ACCESS_DENIED", dataPackage.packageId(), ErrorCode.AAD_MISMATCH, "grant policy hash mismatch");
        }
        if (grant.contentKeyVersion() != dataPackage.contentKeyVersion()) {
            deny(actorId, "GRANT_ACCESS_DENIED", dataPackage.packageId(), ErrorCode.GRANT_ROTATED, "content key version mismatch");
        }
        String expectedGrantContextHash = Hash.sha256Hex(AadBuilder.build(DataSecurityService.grantContext(data, grant)));
        if (!expectedGrantContextHash.equals(dataPackage.grantContextHash())) {
            deny(actorId, "GRANT_ACCESS_DENIED", dataPackage.packageId(), ErrorCode.AAD_MISMATCH, "grant context hash mismatch");
        }
    }

    private ShareGrant grantForPackage(ReEncryptedPackage dataPackage) {
        return grantRepository.findById(dataPackage.grantId())
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.GRANT_NOT_FOUND, "grant not found"));
    }

    private void deny(String actor, String action, String target, ErrorCode code, String message) {
        audit.record(new com.example.pre.model.AuditEvent(Instant.now(), actor, action, target, false, code.name()));
        throw new ReKeyShareException(code, message);
    }
}
