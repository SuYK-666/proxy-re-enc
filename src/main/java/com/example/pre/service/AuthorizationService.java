package com.example.pre.service;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.ecc.EccInteractiveReKeyGenerator;
import com.example.pre.crypto.ecc.EccPrivateKeyMaterial;
import com.example.pre.crypto.ecc.EccPublicKeyMaterial;
import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.crypto.ecc.ReKeySessionContext;
import com.example.pre.crypto.rsa.RsaPrivateKeyMaterial;
import com.example.pre.crypto.rsa.RsaPublicKeyMaterial;
import com.example.pre.crypto.rsa.RsaReKeyGenerator;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.User;
import com.example.pre.storage.AuditRepository;

import java.time.Instant;

public final class AuthorizationService {
    private final PreScheme scheme;
    private final AuditRepository audit;

    public AuthorizationService(PreScheme scheme, AuditRepository audit) {
        this.scheme = scheme;
        this.audit = audit;
    }

    public ReEncryptedPackage authorize(User owner, User recipient, EncryptedDataPackage dataPackage) {
        ReEncryptionKey reKey = createReKey(owner, recipient);
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "AUTHORIZE", recipient.userId(), true, scheme.name()));
        EncryptedKeyCapsule transformed = scheme.reEncrypt(dataPackage.originalCapsule(), reKey);
        audit.record(new AuditEvent(Instant.now(), "proxy", "RE_ENCRYPT", dataPackage.dataId(), true, scheme.name()));
        return new ReEncryptedPackage(
                dataPackage.dataId(),
                owner.userId(),
                recipient.userId(),
                dataPackage.algorithm(),
                dataPackage.encryptedContent(),
                dataPackage.contentNonce(),
                dataPackage.aad(),
                transformed,
                Instant.now()
        );
    }

    private ReEncryptionKey createReKey(User owner, User recipient) {
        if (owner.keyPair().privateKey() instanceof RsaPrivateKeyMaterial ownerPrivate
                && recipient.keyPair().publicKey() instanceof RsaPublicKeyMaterial recipientPublic) {
            return new RsaReKeyGenerator().generateReEncryptionKey(ownerPrivate, recipientPublic);
        }
        if (owner.keyPair().privateKey() instanceof EccPrivateKeyMaterial ownerPrivate
                && recipient.keyPair().privateKey() instanceof EccPrivateKeyMaterial recipientPrivate
                && recipient.keyPair().publicKey() instanceof EccPublicKeyMaterial recipientPublic) {
            ReKeySessionContext context = ReKeySessionContext.create();
            EccInteractiveReKeyGenerator generator = new EccInteractiveReKeyGenerator();
            RecipientReKeyShare share = generator.createRecipientShare(recipientPrivate, context);
            return generator.generateReEncryptionKey(ownerPrivate, recipientPublic, share, context);
        }
        throw new IllegalArgumentException("unsupported key material for " + scheme.name());
    }
}
