package com.example.pre.service;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.User;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.DataRepository;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;

import java.time.Instant;
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
        String dataId = UUID.randomUUID().toString();
        byte[] dataKey = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] aad = Bytes.utf8(dataId + "|" + owner.userId() + "|" + scheme.name());
        AesGcm.CipherText content = AesGcm.encrypt(dataKey, plaintext, aad);
        EncryptedKeyCapsule capsule = scheme.encapsulate(dataKey, owner.keyPair().publicKey());
        EncryptedDataPackage dataPackage = new EncryptedDataPackage(
                dataId,
                owner.userId(),
                capsule.algorithm(),
                content.ciphertext(),
                content.nonce(),
                aad,
                capsule,
                Instant.now()
        );
        dataRepository.save(dataPackage);
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "UPLOAD_ENCRYPTED", dataId, true, scheme.name()));
        return dataPackage;
    }

    public byte[] decryptOriginal(User owner, EncryptedDataPackage dataPackage) {
        byte[] dataKey = scheme.decapsulate(dataPackage.originalCapsule(), owner.keyPair().privateKey());
        byte[] plaintext = AesGcm.decrypt(dataKey, dataPackage.contentNonce(), dataPackage.encryptedContent(), dataPackage.aad());
        audit.record(new AuditEvent(Instant.now(), owner.userId(), "DECRYPT_ORIGINAL", dataPackage.dataId(), true, scheme.name()));
        return plaintext;
    }

    public byte[] decryptReEncrypted(User recipient, ReEncryptedPackage dataPackage) {
        byte[] dataKey = scheme.decapsulate(dataPackage.reEncryptedCapsule(), recipient.keyPair().privateKey());
        byte[] plaintext = AesGcm.decrypt(dataKey, dataPackage.contentNonce(), dataPackage.encryptedContent(), dataPackage.aad());
        audit.record(new AuditEvent(Instant.now(), recipient.userId(), "DECRYPT_REENCRYPTED", dataPackage.dataId(), true, scheme.name()));
        return plaintext;
    }
}
