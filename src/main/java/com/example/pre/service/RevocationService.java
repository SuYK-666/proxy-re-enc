package com.example.pre.service;

import com.example.pre.crypto.PreScheme;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.PackageStatus;
import com.example.pre.model.GrantStatus;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.DataRepository;
import com.example.pre.storage.GrantRepository;
import com.example.pre.storage.ReEncryptedPackageRepository;

import java.time.Instant;

public final class RevocationService {
    private final PreScheme scheme;
    private final DataRepository dataRepository;
    private final GrantRepository grantRepository;
    private final ObjectAuthorizationService authorization;
    private final AuditRepository audit;
    private final ReEncryptedPackageRepository packageRepository;

    public RevocationService(
            PreScheme scheme,
            DataRepository dataRepository,
            GrantRepository grantRepository,
            ObjectAuthorizationService authorization,
            AuditRepository audit
    ) {
        this(scheme, dataRepository, grantRepository, null, authorization, audit);
    }

    public RevocationService(
            PreScheme scheme,
            DataRepository dataRepository,
            GrantRepository grantRepository,
            ReEncryptedPackageRepository packageRepository,
            ObjectAuthorizationService authorization,
            AuditRepository audit
    ) {
        this.scheme = scheme;
        this.dataRepository = dataRepository;
        this.grantRepository = grantRepository;
        this.authorization = authorization;
        this.audit = audit;
        this.packageRepository = packageRepository;
    }

    public ShareGrant revokeGrant(String ownerId, String grantId) {
        return revokeGrant(ownerId, grantId, "owner requested revoke");
    }

    public ShareGrant revokeGrant(String ownerId, String grantId, String reason) {
        ShareGrant existing = authorization.assertCanRevokeGrant(ownerId, grantId);
        new StateTransitionGuard().grant(existing.status(), GrantStatus.REVOKED);
        ShareGrant grant = existing.revoke(reason);
        grantRepository.save(grant);
        if (packageRepository != null) {
            packageRepository.findAll().stream()
                    .filter(dataPackage -> grantId.equals(dataPackage.grantId()))
                    .filter(dataPackage -> dataPackage.status() == PackageStatus.ACTIVE)
                    .forEach(dataPackage -> {
                        new StateTransitionGuard().dataPackage(dataPackage.status(), PackageStatus.INVALIDATED);
                        packageRepository.save(dataPackage.invalidate(PackageStatus.INVALIDATED, "grant revoked"));
                    });
        }
        audit.record(new AuditEvent(Instant.now(), ownerId, "GRANT_REVOKE", grantId, true,
                "packages invalidated; reason=" + reason));
        return grant;
    }

    public EncryptedDataPackage acceptOwnerSideRotation(User owner, EncryptedDataPackage preparedRotation) {
        EncryptedDataPackage current = dataRepository.findById(preparedRotation.dataId())
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.DATA_NOT_FOUND, "data not found"));
        if (!current.ownerId().equals(owner.userId())) {
            throw new ReKeyShareException(ErrorCode.ACCESS_DENIED, "only owner can rotate content key");
        }
        if (preparedRotation.contentKeyVersion() != current.contentKeyVersion() + 1) {
            throw new ReKeyShareException(ErrorCode.AAD_MISMATCH, "owner-side rotation must increment contentKeyVersion by one");
        }
        if (preparedRotation.algorithm() != current.algorithm()) {
            throw new ReKeyShareException(ErrorCode.ALGORITHM_MISMATCH, "owner-side rotation algorithm mismatch");
        }
        for (ShareGrant grant : grantRepository.findByDataId(current.dataId())) {
            if (grant.status() == GrantStatus.ACTIVE) {
                new StateTransitionGuard().grant(grant.status(), GrantStatus.ROTATED);
                grantRepository.save(grant.rotate());
            }
        }
        if (packageRepository != null) {
            packageRepository.findAll().stream()
                    .filter(dataPackage -> current.dataId().equals(dataPackage.dataId()))
                    .filter(dataPackage -> dataPackage.status() == PackageStatus.ACTIVE)
                    .forEach(dataPackage -> {
                        new StateTransitionGuard().dataPackage(dataPackage.status(), PackageStatus.ROTATED);
                        packageRepository.save(dataPackage.invalidate(PackageStatus.ROTATED, "owner-side content key rotated"));
                    });
        }
        dataRepository.save(preparedRotation);
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "KEY_ROTATE_OWNER_SIDE", current.dataId(), true,
                "contentKeyVersion=" + preparedRotation.contentKeyVersion()));
        return preparedRotation;
    }
}
