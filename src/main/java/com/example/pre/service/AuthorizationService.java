package com.example.pre.service;

import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.ScopedReEncryptionKey;
import com.example.pre.crypto.ecc.EccInteractiveReKeyGenerator;
import com.example.pre.crypto.ecc.EccPrivateKeyMaterial;
import com.example.pre.crypto.ecc.EccPublicKeyMaterial;
import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.crypto.ecc.ReKeySessionContext;
import com.example.pre.crypto.rsa.RsaPrivateKeyMaterial;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.crypto.rsa.RsaPublicKeyMaterial;
import com.example.pre.crypto.rsa.RsaReKeyGenerator;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.RecipientShareSubmission;
import com.example.pre.model.ReKeySession;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.GrantRepository;
import com.example.pre.util.PolicyDigest;

import java.time.Instant;

public final class AuthorizationService {
    private final PreScheme scheme;
    private final AuditRepository audit;
    private final GrantRepository grants;

    public AuthorizationService(PreScheme scheme, AuditRepository audit) {
        this(scheme, audit, null);
    }

    public AuthorizationService(PreScheme scheme, AuditRepository audit, GrantRepository grants) {
        this.scheme = scheme;
        this.audit = audit;
        this.grants = grants;
    }

    @Deprecated(forRemoval = true)
    public ReEncryptedPackage authorize(User owner, User recipient, EncryptedDataPackage dataPackage) {
        throw new UnsupportedOperationException(
                "Legacy authorize() is disabled. Use createGrant() + ProxyReEncryptionService.reEncrypt()."
        );
    }

    public ShareGrant createGrant(User owner, User recipient, EncryptedDataPackage dataPackage, AccessPolicy policy) {
        ensureOwnerCanGrant(owner, dataPackage);
        String policyHash = PolicyDigest.sha256(policy);
        ShareGrant grant = ShareGrant.active(
                dataPackage.dataId(),
                owner.userId(),
                recipient.userId(),
                dataPackage.algorithm(),
                policy,
                policyHash,
                createReKey(owner, recipient),
                dataPackage.contentKeyVersion()
        );
        grant = bindReKeyScope(grant);
        saveGrant(grant);
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "GRANT_CREATE", grant.grantId(), true, policyHash));
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "REKEY_GENERATE", grant.grantId(), true, scheme.name()));
        return grant;
    }

    public ShareGrant createGrantWithRecipientShare(
            User owner,
            User recipient,
            EncryptedDataPackage dataPackage,
            AccessPolicy policy,
            RecipientReKeyShare share,
            ReKeySessionContext context
    ) {
        ensureOwnerCanGrant(owner, dataPackage);
        if (dataPackage.algorithm() != AlgorithmType.ECC_PRE || scheme.algorithm() != AlgorithmType.ECC_PRE) {
            throw new ReKeyShareException(ErrorCode.ALGORITHM_MISMATCH, "ECC recipient share requires ECC data and ECC scheme");
        }
        if (!(owner.keyPair().privateKey() instanceof EccPrivateKeyMaterial ownerPrivate)
                || !(recipient.keyPair().publicKey() instanceof EccPublicKeyMaterial recipientPublic)) {
            throw new ReKeyShareException(ErrorCode.INVALID_RECIPIENT_SHARE, "ECC recipient share requires ECC key material");
        }
        String policyHash = PolicyDigest.sha256(policy);
        ReEncryptionKey reKey = new EccInteractiveReKeyGenerator().generateReEncryptionKey(ownerPrivate, recipientPublic, share, context);
        ShareGrant grant = ShareGrant.active(dataPackage.dataId(), owner.userId(), recipient.userId(), dataPackage.algorithm(),
                policy, policyHash, reKey, dataPackage.contentKeyVersion());
        grant = bindReKeyScope(grant);
        saveGrant(grant);
        audit.record(new AuditEvent(Instant.now(), recipient.userId(), "RECIPIENT_SHARE_SUBMIT", grant.grantId(), true, "private-key-local"));
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "GRANT_CREATE", grant.grantId(), true, policyHash));
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "REKEY_GENERATE", grant.grantId(), true, scheme.name()));
        return grant;
    }

    public ShareGrant createGrantFromVerifiedRecipientShare(
            User owner,
            User recipient,
            EncryptedDataPackage dataPackage,
            AccessPolicy policy,
            EccRecipientShareService shareService,
            String sessionId
    ) {
        ReKeySession session = shareService.requireCompleted(sessionId);
        RecipientShareSubmission submission = shareService.requireVerifiedSubmission(sessionId);
        if (!session.dataId().equals(dataPackage.dataId())
                || !session.ownerId().equals(owner.userId())
                || !session.recipientId().equals(recipient.userId())) {
            throw new ReKeyShareException(ErrorCode.INVALID_REKEY_SESSION, "session context mismatch");
        }
        ShareGrant grant = createGrantWithRecipientShare(
                owner, recipient, dataPackage, policy, submission.recipientShare(), session.cryptoContext());
        shareService.complete(sessionId);
        return grant;
    }

    public ReEncryptionKey createReKey(User owner, User recipient) {
        if (owner.keyPair().privateKey() == null) {
            throw new ReKeyShareException(ErrorCode.CLIENT_KEY_REQUIRED,
                    "production grant requires client-generated re-encryption material");
        }
        if (owner.keyPair().privateKey() instanceof RsaPrivateKeyMaterial ownerPrivate
                && recipient.keyPair().publicKey() instanceof RsaPublicKeyMaterial recipientPublic) {
            if (!(scheme instanceof RsaPreScheme rsaScheme)) {
                throw new ReKeyShareException(ErrorCode.ALGORITHM_MISMATCH, "RSA re-key requires RSA scheme parameters");
            }
            return rsaScheme.generateBaselineReEncryptionKey(ownerPrivate, recipientPublic);
        }
        if (owner.keyPair().privateKey() instanceof EccPrivateKeyMaterial) {
            throw new ReKeyShareException(ErrorCode.INVALID_RECIPIENT_SHARE,
                    "ECC grant creation requires a recipient share generated outside the service");
        }
        throw new IllegalArgumentException("unsupported key material for " + scheme.name());
    }

    private void saveGrant(ShareGrant grant) {
        if (grants == null) {
            throw new IllegalStateException("GrantRepository is required for lifecycle grants");
        }
        grants.save(grant);
    }

    private static ShareGrant bindReKeyScope(ShareGrant grant) {
        return grant.withReKey(new ScopedReEncryptionKey(grant.reKey(), grant.grantId(), grant.dataId(),
                grant.recipientId(), grant.contentKeyVersion(), grant.policyHash(), grant.expiresAt(),
                grant.policy().maxReEncryptCount()));
    }

    private com.example.pre.model.AlgorithmType schemeFromUser(User owner) {
        return owner.keyPair().publicKey() instanceof RsaPublicKeyMaterial
                ? com.example.pre.model.AlgorithmType.RSA_PRE
                : com.example.pre.model.AlgorithmType.ECC_PRE;
    }

    private void ensureOwnerCanGrant(User owner, EncryptedDataPackage dataPackage) {
        if (!dataPackage.ownerId().equals(owner.userId())) {
            audit.record(new AuditEvent(Instant.now(), owner.userId(), "UNAUTHORIZED_ACCESS", dataPackage.dataId(), false, "ACCESS_DENIED"));
            throw new ReKeyShareException(ErrorCode.ACCESS_DENIED, "only data owner can create a grant");
        }
        if (dataPackage.algorithm() != schemeFromUser(owner) || dataPackage.algorithm() != scheme.algorithm()) {
            throw new ReKeyShareException(ErrorCode.ALGORITHM_MISMATCH, "grant algorithm does not match service scheme");
        }
    }
}
