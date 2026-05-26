package com.example.pre.crypto.provider;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.UserKeyPair;

public final class BaselineEccProvider implements CryptoProvider {
    private final EccPreScheme scheme = new EccPreScheme();

    public EccPreScheme scheme() {
        return scheme;
    }

    @Override
    public SchemeDescriptor descriptor() {
        return new SchemeDescriptor("ECC_PRE_BASELINE", "Experimental P-256 transformation", "EXPERIMENTAL",
                scheme.parameterSpec(), true, true, false, "NOT_PRODUCTION_REVIEWED", "IMPLEMENTED");
    }

    @Override
    public UserKeyPair generateKeyPair(String userId) {
        return scheme.generateKeyPair(userId);
    }

    @Override
    public EncryptedKeyCapsule encapsulate(byte[] dek, PublicKeyMaterial recipient, CapsuleContext context) {
        return scheme.encapsulate(dek, recipient, context);
    }

    @Override
    public EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule capsule, ReEncryptionKey reKey, CapsuleContext context) {
        return scheme.reEncrypt(capsule, reKey, context);
    }

    @Override
    public byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial recipientPrivateKey, CapsuleContext context) {
        return scheme.decapsulate(capsule, recipientPrivateKey, context);
    }
}
