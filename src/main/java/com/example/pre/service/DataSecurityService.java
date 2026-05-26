package com.example.pre.service;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.DataRepository;
import com.example.pre.util.AadBuilder;
import com.example.pre.util.SecureRandomUtil;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

public final class DataSecurityService {
    private final PreScheme scheme;
    private final DataRepository dataRepository;
    private final AuditRepository audit;

    public DataSecurityService(PreScheme scheme, DataRepository dataRepository, AuditRepository audit) {
        this.scheme = scheme;
        this.dataRepository = dataRepository;
        this.audit = audit;
    }

    public EncryptedDataPackage upload(User owner, byte[] plaintext) {
        return upload(new UploadDataCommand(owner, plaintext, "demo-" + UUID.randomUUID() + ".txt", "text/plain"));
    }

    public EncryptedDataPackage upload(UploadDataCommand command) {
        User owner = command.owner();
        byte[] plaintext = command.plaintext();
        String dataId = UUID.randomUUID().toString();
        byte[] dataKey = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        String ownerKeyId = "demo-key-" + owner.userId();
        String policyHash = "OWNER_UPLOAD";
        CapsuleContext capsuleContext = capsuleContext(dataId, owner.userId(), algorithm(), ownerKeyId, 1, policyHash);
        byte[] aad = AadBuilder.build(capsuleContext);
        AesGcm.CipherText content = AesGcm.encrypt(dataKey, plaintext, aad);
        EncryptedKeyCapsule capsule = scheme.encapsulate(dataKey, owner.keyPair().publicKey(), capsuleContext);
        EncryptedDataPackage dataPackage = EncryptedDataPackage.uploadedEncrypted(
                dataId,
                owner.userId(),
                capsule.algorithm(),
                content.ciphertext(),
                content.nonce(),
                aad,
                capsule,
                plaintext.length,
                command.fileName(),
                command.contentType(),
                ownerKeyId,
                1,
                policyHash,
                com.example.pre.crypto.hash.Hash.sha256Hex(aad)
        );
        dataRepository.save(dataPackage);
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "DATA_UPLOAD", dataId, true, command.fileName()));
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "DATA_ENCRYPT", dataId, true, scheme.name()));
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "UPLOAD_ENCRYPTED", dataId, true, scheme.name()));
        Arrays.fill(dataKey, (byte) 0);
        return dataPackage;
    }

    public EncryptedDataPackage uploadEncrypted(UploadEncryptedCommand command) {
        User owner = command.owner();
        if (command.encryptedContent() == null || command.encryptedContent().length == 0) {
            throw new ReKeyShareException(ErrorCode.INVALID_REQUEST, "encryptedContent is required");
        }
        if (command.contentNonce() == null || command.contentNonce().length == 0) {
            throw new ReKeyShareException(ErrorCode.INVALID_REQUEST, "contentNonce is required");
        }
        if (command.aad() == null || command.aad().length == 0) {
            throw new ReKeyShareException(ErrorCode.INVALID_REQUEST, "aad is required");
        }
        if (command.originalCapsule() == null) {
            throw new ReKeyShareException(ErrorCode.INVALID_REQUEST, "originalCapsule is required");
        }
        byte[] expectedAad = AadBuilder.build(command.context());
        if (!java.util.Arrays.equals(expectedAad, command.aad())) {
            throw new ReKeyShareException(ErrorCode.CRYPTO_CONTEXT_MISMATCH,
                    "AAD must match canonical capsule context");
        }
        scheme.validateCapsule(command.originalCapsule(), command.context());
        EncryptedDataPackage dataPackage = EncryptedDataPackage.uploadedEncrypted(
                command.context().dataId(),
                owner.userId(),
                command.context().algorithm(),
                command.encryptedContent(),
                command.contentNonce(),
                command.aad(),
                command.originalCapsule(),
                command.originalSize(),
                command.fileName(),
                command.contentType(),
                command.context().ownerKeyId(),
                command.context().contentKeyVersion(),
                command.context().policyHash(),
                com.example.pre.crypto.hash.Hash.sha256Hex(command.aad())
        );
        dataRepository.save(dataPackage);
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "UPLOAD_ENCRYPTED", dataPackage.dataId(), true, scheme.name()));
        return dataPackage;
    }

    public byte[] decryptOriginal(User owner, EncryptedDataPackage dataPackage) {
        byte[] dataKey = scheme.decapsulate(dataPackage.originalCapsule(), owner.keyPair().privateKey(), capsuleContext(dataPackage));
        try {
            byte[] plaintext = AesGcm.decrypt(dataKey, dataPackage.contentNonce(), dataPackage.encryptedContent(), dataPackage.aad());
            audit.record(new AuditEvent(Instant.now(), owner.userId(), "DECRYPT_ORIGINAL", dataPackage.dataId(), true, scheme.name()));
            return plaintext;
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }

    public byte[] decryptReEncrypted(User recipient, ReEncryptedPackage dataPackage) {
        byte[] dataKey = scheme.decapsulate(dataPackage.reEncryptedCapsule(), recipient.keyPair().privateKey(), capsuleContext(dataPackage));
        try {
            byte[] plaintext = AesGcm.decrypt(dataKey, dataPackage.contentNonce(), dataPackage.encryptedContent(), dataPackage.aad());
            audit.record(new AuditEvent(Instant.now(), recipient.userId(), "DECRYPT_REENCRYPTED", dataPackage.dataId(), true, scheme.name()));
            return plaintext;
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }

    public record UploadDataCommand(User owner, byte[] plaintext, String fileName, String contentType) {
    }

    public record UploadEncryptedCommand(
            User owner,
            byte[] encryptedContent,
            byte[] contentNonce,
            byte[] aad,
            EncryptedKeyCapsule originalCapsule,
            CapsuleContext context,
            long originalSize,
            String fileName,
            String contentType
    ) {
    }

    private AlgorithmType algorithm() {
        return scheme.algorithm();
    }

    public static CapsuleContext capsuleContext(EncryptedDataPackage dataPackage) {
        return capsuleContext(
                dataPackage.dataId(),
                dataPackage.ownerId(),
                dataPackage.algorithm(),
                dataPackage.ownerKeyId(),
                dataPackage.contentKeyVersion(),
                dataPackage.policyHash()
        );
    }

    public static CapsuleContext capsuleContext(ReEncryptedPackage dataPackage) {
        return capsuleContext(
                dataPackage.dataId(),
                dataPackage.ownerId(),
                dataPackage.algorithm(),
                dataPackage.ownerKeyId(),
                dataPackage.contentKeyVersion(),
                dataPackage.policyHash()
        );
    }

    public static CapsuleContext grantContext(EncryptedDataPackage dataPackage, ShareGrant grant) {
        return new CapsuleContext(
                dataPackage.dataId(),
                dataPackage.ownerId(),
                grant.recipientId(),
                dataPackage.algorithm(),
                dataPackage.ownerKeyId(),
                dataPackage.contentKeyVersion(),
                grant.policyHash(),
                "tenant-default",
                grant.grantId(),
                dataPackage.algorithm().name(),
                "proxy",
                "RE_ENCRYPT"
        );
    }

    private static CapsuleContext capsuleContext(
            String dataId,
            String ownerId,
            AlgorithmType algorithm,
            String ownerKeyId,
            int contentKeyVersion,
            String policyHash
    ) {
        return new CapsuleContext(dataId, ownerId, ownerId, algorithm, ownerKeyId, contentKeyVersion, policyHash);
    }
}
