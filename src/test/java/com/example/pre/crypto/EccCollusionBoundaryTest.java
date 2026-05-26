package com.example.pre.crypto;

import com.example.pre.crypto.ecc.EccInteractiveReKeyGenerator;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.ecc.EccPrivateKeyMaterial;
import com.example.pre.crypto.ecc.EccReEncryptionKey;
import com.example.pre.crypto.ecc.P256Curve;
import com.example.pre.crypto.ecc.ReKeySessionContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Documents why ECC_PRE is a teaching baseline, not a production PRE claim.
 */
class EccCollusionBoundaryTest {
    @Test
    void proxyRekeyAndRecipientPrivateKeyRevealOwnerScalarInBaseline() {
        EccPreScheme scheme = new EccPreScheme();
        var owner = scheme.generateKeyPair("owner");
        var recipient = scheme.generateKeyPair("recipient");
        EccPrivateKeyMaterial ownerPrivate = (EccPrivateKeyMaterial) owner.privateKey();
        EccPrivateKeyMaterial recipientPrivate = (EccPrivateKeyMaterial) recipient.privateKey();
        EccInteractiveReKeyGenerator generator = new EccInteractiveReKeyGenerator();
        ReKeySessionContext context = ReKeySessionContext.create();

        var share = generator.createRecipientShare(recipientPrivate, context);
        EccReEncryptionKey proxyRekey = (EccReEncryptionKey) generator.generateReEncryptionKey(
                ownerPrivate, (com.example.pre.crypto.ecc.EccPublicKeyMaterial) recipient.publicKey(),
                share, context);

        var recoveredOwnerScalar = proxyRekey.scalar().multiply(recipientPrivate.scalar()).mod(P256Curve.N);
        assertEquals(ownerPrivate.scalar(), recoveredOwnerScalar);
    }
}
