package com.example.pre.service;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.ScopedReEncryptionKey;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.PackageManifest;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.UserRole;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.DataRepository;
import com.example.pre.storage.GrantRepository;
import com.example.pre.storage.ReEncryptedPackageRepository;

import java.time.Instant;

public final class ProxyReEncryptionService {
    private final PreScheme scheme;
    private final DataRepository dataRepository;
    private final GrantRepository grantRepository;
    private final ReEncryptedPackageRepository packageRepository;
    private final ObjectAuthorizationService authorization;
    private final AuditRepository audit;

    public ProxyReEncryptionService(
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
        this.packageRepository = packageRepository;
        this.authorization = authorization;
        this.audit = audit;
    }

    public ReEncryptedPackage reEncrypt(SecurityContext proxyActor, String grantId) {
        synchronized (grantRepository) {
            ShareGrant grant = authorization.assertCanReEncryptGrant(proxyActor, grantId);
            EncryptedDataPackage data = dataRepository.findById(grant.dataId())
                    .orElseThrow(() -> new ReKeyShareException(ErrorCode.DATA_NOT_FOUND, "data not found"));
            if (data.contentKeyVersion() != grant.contentKeyVersion()) {
                throw new ReKeyShareException(ErrorCode.KEY_REVOKED, "grant is bound to an old content key version");
            }
            var ownerContext = DataSecurityService.capsuleContext(data);
            var grantContext = DataSecurityService.grantContext(data, grant);
            ReEncryptionKey reKey = grant.reKey();
            if (reKey instanceof ScopedReEncryptionKey scoped) {
                reKey = scoped.consume(grant.grantId(), data.dataId(), grant.recipientId(),
                        grant.contentKeyVersion(), grant.policyHash(), Instant.now());
            }
            EncryptedKeyCapsule transformed = scheme.reEncrypt(data.originalCapsule(), reKey, ownerContext);
            ReEncryptedPackage dataPackage = new ReEncryptedPackage(
                    java.util.UUID.randomUUID().toString(),
                    grant.grantId(),
                    data.dataId(),
                    data.ownerId(),
                    grant.recipientId(),
                    data.algorithm(),
                    data.encryptedContent(),
                    data.contentNonce(),
                    data.aad(),
                    transformed,
                    Instant.now(),
                    data.contentKeyVersion(),
                    data.storagePath(),
                    data.ownerKeyId(),
                    data.policyHash(),
                    grant.policyHash(),
                    data.contextHash(),
                    com.example.pre.crypto.hash.Hash.sha256Hex(com.example.pre.util.AadBuilder.build(grantContext)),
                    com.example.pre.util.AadBuilder.build(grantContext),
                    com.example.pre.model.PackageStatus.ACTIVE,
                    null,
                    "",
                    ""
            );
            dataPackage = dataPackage.withIssuedManifestHash(PackageManifest.issue(dataPackage).manifestHash());
            packageRepository.save(dataPackage);
            grantRepository.save(grant.incrementReEncrypt());
            audit.record(new AuditEvent(Instant.now(), proxyActor.userId(), "PROXY_REENCRYPT", dataPackage.packageId(), true, scheme.name()));
            return dataPackage;
        }
    }

    /**
     * Demo and legacy tests use a fixed proxy principal. Production API paths must call
     * the SecurityContext overload so proxy authority comes from a signed role.
     */
    public ReEncryptedPackage reEncrypt(String demoProxyActorId, String grantId) {
        SecurityContext demoProxy = new SecurityContext(
                demoProxyActorId,
                UserRole.PROXY,
                "demo",
                "demo-fixture",
                Instant.now().getEpochSecond(),
                Instant.now().plusSeconds(300).getEpochSecond()
        );
        return reEncrypt(demoProxy, grantId);
    }
}
