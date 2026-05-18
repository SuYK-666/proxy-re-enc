package com.example.pre.crypto.ecc;

import com.example.pre.crypto.ReEncryptionKey;

public final class EccInteractiveReKeyGenerator {
    public RecipientReKeyShare createRecipientShare(
            EccPrivateKeyMaterial recipientPrivateKey,
            ReKeySessionContext context
    ) {
        if (context == null) {
            throw new IllegalArgumentException("session context is required");
        }
        return new RecipientReKeyShare(recipientPrivateKey.scalar().modInverse(P256Curve.N));
    }

    public ReEncryptionKey generateReEncryptionKey(
            EccPrivateKeyMaterial ownerPrivateKey,
            EccPublicKeyMaterial recipientPublicKey,
            RecipientReKeyShare recipientShare,
            ReKeySessionContext context
    ) {
        if (recipientPublicKey == null || context == null) {
            throw new IllegalArgumentException("recipient public key and session context are required");
        }
        return new EccReEncryptionKey(
                ownerPrivateKey.scalar()
                        .multiply(recipientShare.inverseRecipientScalar())
                        .mod(P256Curve.N)
        );
    }
}
