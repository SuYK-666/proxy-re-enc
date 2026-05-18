package com.example.pre.crypto;

import com.example.pre.crypto.ecc.EccInteractiveReKeyGenerator;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.ecc.EccPrivateKeyMaterial;
import com.example.pre.crypto.ecc.EccPublicKeyMaterial;
import com.example.pre.crypto.ecc.P256Curve;
import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.crypto.ecc.ReKeySessionContext;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EccPreSchemeTest {
    @Test
    void reEncryptsCapsuleFromOwnerToRecipient() {
        EccPreScheme scheme = new EccPreScheme();
        UserKeyPair alice = scheme.generateKeyPair("alice");
        UserKeyPair bob = scheme.generateKeyPair("bob");
        byte[] dataKey = SecureRandomUtil.randomBytes(32);

        EncryptedKeyCapsule original = scheme.encapsulate(dataKey, alice.publicKey());
        assertArrayEquals(dataKey, scheme.decapsulate(original, alice.privateKey()));
        assertThrows(RuntimeException.class, () -> scheme.decapsulate(original, bob.privateKey()));

        ReEncryptionKey reKey = createReKey(alice, bob);
        EncryptedKeyCapsule transformed = scheme.reEncrypt(original, reKey);
        assertArrayEquals(dataKey, scheme.decapsulate(transformed, bob.privateKey()));
    }

    @Test
    void curveBasePointHasExpectedOrder() {
        P256Curve curve = new P256Curve();
        assertTrue(curve.isOnCurve(P256Curve.G));
        assertTrue(curve.multiply(P256Curve.N, P256Curve.G).infinity());
        assertFalse(curve.multiply(BigInteger.valueOf(2), P256Curve.G).infinity());
    }

    @Test
    void rejectsTamperedPointHeader() {
        EccPreScheme scheme = new EccPreScheme();
        UserKeyPair alice = scheme.generateKeyPair("alice");
        byte[] dataKey = SecureRandomUtil.randomBytes(32);
        EncryptedKeyCapsule original = scheme.encapsulate(dataKey, alice.publicKey());
        byte[] tamperedHeader = original.header().clone();
        tamperedHeader[10] ^= 1;

        EncryptedKeyCapsule tampered = new EncryptedKeyCapsule(
                original.algorithm(),
                tamperedHeader,
                original.wrappedKey(),
                original.keyNonce()
        );
        assertThrows(RuntimeException.class, () -> scheme.decapsulate(tampered, alice.privateKey()));
    }

    private static ReEncryptionKey createReKey(UserKeyPair alice, UserKeyPair bob) {
        EccInteractiveReKeyGenerator generator = new EccInteractiveReKeyGenerator();
        ReKeySessionContext context = ReKeySessionContext.create();
        RecipientReKeyShare share = generator.createRecipientShare(
                (EccPrivateKeyMaterial) bob.privateKey(),
                context
        );
        return generator.generateReEncryptionKey(
                (EccPrivateKeyMaterial) alice.privateKey(),
                (EccPublicKeyMaterial) bob.publicKey(),
                share,
                context
        );
    }
}
