package com.example.pre.crypto.rsa;

import com.example.pre.crypto.ReEncryptionKey;

public final class RsaReKeyGenerator {
    public ReEncryptionKey generateReEncryptionKey(
            RsaPrivateKeyMaterial ownerPrivateKey,
            RsaPublicKeyMaterial recipientPublicKey,
            java.math.BigInteger phi
    ) {
        if (!ownerPrivateKey.modulus().equals(recipientPublicKey.modulus())) {
            throw new IllegalArgumentException("RSA-PRE requires the shared modulus parameters");
        }
        return new RsaReEncryptionKey(
                ownerPrivateKey.modulus(),
                ownerPrivateKey.privateExponent()
                        .multiply(recipientPublicKey.exponent())
                        .mod(phi)
        );
    }
}
