package com.example.pre.crypto.provider;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.UserKeyPair;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.util.AadBuilder;

/**
 * Exposes the standards-based direct-recipient envelope provider to the service layer.
 * Proxy transformation is deliberately unsupported for this profile.
 */
public final class SecureEnvelopeSchemeAdapter implements PreScheme {
    private final SecureEnvelopeProvider provider = new SecureEnvelopeProvider();

    @Override
    public String name() {
        return provider.descriptor().schemeId();
    }

    @Override
    public AlgorithmType algorithm() {
        return AlgorithmType.SECURE_ENVELOPE;
    }

    @Override
    public String parameterSpec() {
        return provider.descriptor().parameterSpec();
    }

    @Override
    public UserKeyPair generateKeyPair(String userId) {
        return provider.generateKeyPair(userId);
    }

    @Override
    public EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial publicKey) {
        return provider.encapsulate(dataKey, publicKey, null);
    }

    @Override
    public EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial publicKey, CapsuleContext context) {
        return provider.encapsulate(dataKey, publicKey, context);
    }

    @Override
    public byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey) {
        return provider.decapsulate(capsule, privateKey, null);
    }

    @Override
    public byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey, CapsuleContext context) {
        return provider.decapsulate(capsule, privateKey, context);
    }

    @Override
    public EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule capsule, ReEncryptionKey reKey) {
        throw new UnsupportedOperationException("secure envelope does not expose proxy transformation");
    }

    @Override
    public void validateCapsule(EncryptedKeyCapsule capsule, CapsuleContext context) {
        if (capsule.algorithm() != AlgorithmType.SECURE_ENVELOPE) {
            throw new IllegalArgumentException("secure envelope algorithm mismatch");
        }
        if (context != null && context.algorithm() != AlgorithmType.SECURE_ENVELOPE) {
            throw new IllegalArgumentException("secure envelope context mismatch");
        }
        if (context != null && !Hash.sha256Hex(AadBuilder.build(context)).equals(capsule.aadHash())) {
            throw new IllegalArgumentException("secure envelope AAD digest mismatch");
        }
    }
}
