package com.example.pre.crypto;

import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.ReKeyGenerationRequest;
import com.example.pre.model.UserKeyPair;

public interface PreScheme {
    String name();

    default AlgorithmType algorithm() {
        return name().equals("RSA-PRE") ? AlgorithmType.RSA_PRE : AlgorithmType.ECC_PRE;
    }

    default String parameterSpec() {
        return algorithm().name() + "-teaching-prototype";
    }

    UserKeyPair generateKeyPair(String userId);

    @Deprecated(forRemoval = true)
    EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial ownerPublicKey);

    default EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial ownerPublicKey, CapsuleContext context) {
        return encapsulate(dataKey, ownerPublicKey);
    }

    @Deprecated(forRemoval = true)
    byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey);

    default byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey, CapsuleContext context) {
        validateCapsule(capsule, context);
        return decapsulate(capsule, privateKey);
    }

    @Deprecated(forRemoval = true)
    EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey);

    default ReEncryptionKey generateReKey(ReKeyGenerationRequest request) {
        throw new UnsupportedOperationException("scheme-specific re-key generation is handled by authorization services");
    }

    default EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey, CapsuleContext context) {
        validateCapsule(originalCapsule, context);
        return reEncrypt(originalCapsule, reKey);
    }

    default void validateCapsule(EncryptedKeyCapsule capsule, CapsuleContext context) {
        if (capsule.algorithm() != algorithm()) {
            throw new IllegalArgumentException("algorithm mismatch");
        }
    }
}
