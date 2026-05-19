package com.example.pre.service;

import com.example.pre.crypto.PreScheme;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.KeyStatus;
import com.example.pre.model.KeyVersion;
import com.example.pre.model.User;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.KeyRepository;

import java.time.Instant;

public final class KeyManagementService {
    private final PreScheme scheme;
    private final KeyRepository keyRepository;
    private final AuditRepository audit;

    public KeyManagementService(PreScheme scheme, KeyRepository keyRepository, AuditRepository audit) {
        this.scheme = scheme;
        this.keyRepository = keyRepository;
        this.audit = audit;
    }

    public KeyVersion registerActiveKey(User user) {
        int version = keyRepository.findByUserId(user.userId()).size() + 1;
        KeyVersion key = KeyVersion.active(user.userId(), algorithm(), version, user.keyPair().publicKey());
        keyRepository.save(key);
        audit.record(new AuditEvent(Instant.now(), user.userId(), "KEY_GENERATE", key.keyId(), true, scheme.name()));
        return key;
    }

    public KeyVersion revokeKey(String actorId, String keyId) {
        KeyVersion current = keyRepository.findById(keyId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.KEY_REVOKED, "key not found"));
        KeyVersion revoked = current.revoke("manual revoke");
        keyRepository.save(revoked);
        audit.record(new AuditEvent(Instant.now(), actorId, "KEY_REVOKE", keyId, true, ""));
        return revoked;
    }

    public KeyVersion rotateKey(User user) {
        for (KeyVersion key : keyRepository.findByUserId(user.userId())) {
            if (key.status() == KeyStatus.ACTIVE) {
                keyRepository.save(key.withStatus(KeyStatus.ROTATED));
            }
        }
        return registerActiveKey(user);
    }

    private AlgorithmType algorithm() {
        return "RSA-PRE".equals(scheme.name()) ? AlgorithmType.RSA_PRE : AlgorithmType.ECC_PRE;
    }
}
