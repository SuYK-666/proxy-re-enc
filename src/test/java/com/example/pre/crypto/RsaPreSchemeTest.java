package com.example.pre.crypto;

import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.crypto.rsa.RsaPublicKeyMaterial;
import com.example.pre.crypto.rsa.RsaReKeyGenerator;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaPreSchemeTest {
    @Test
    void reEncryptsCapsuleFromOwnerToRecipient() {
        RsaPreScheme scheme = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        UserKeyPair alice = scheme.generateKeyPair("alice");
        UserKeyPair bob = scheme.generateKeyPair("bob");
        byte[] dataKey = SecureRandomUtil.randomBytes(32);

        EncryptedKeyCapsule original = scheme.encapsulate(dataKey, alice.publicKey());
        assertArrayEquals(dataKey, scheme.decapsulate(original, alice.privateKey()));
        assertThrows(RuntimeException.class, () -> scheme.decapsulate(original, bob.privateKey()));

        ReEncryptionKey reKey = new RsaReKeyGenerator().generateReEncryptionKey(
                (com.example.pre.crypto.rsa.RsaPrivateKeyMaterial) alice.privateKey(),
                (RsaPublicKeyMaterial) bob.publicKey()
        );
        EncryptedKeyCapsule transformed = scheme.reEncrypt(original, reKey);
        assertArrayEquals(dataKey, scheme.decapsulate(transformed, bob.privateKey()));
    }

    @Test
    void publicExponentsShareNonTrivialFactor() {
        RsaPreScheme scheme = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        UserKeyPair alice = scheme.generateKeyPair("alice");
        UserKeyPair bob = scheme.generateKeyPair("bob");

        BigInteger eAlice = ((RsaPublicKeyMaterial) alice.publicKey()).exponent();
        BigInteger eBob = ((RsaPublicKeyMaterial) bob.publicKey()).exponent();
        assertNotEquals(BigInteger.ONE, eAlice.gcd(eBob));
        assertTrue(eAlice.gcd(eBob).compareTo(BigInteger.ONE) > 0);
    }

    @Test
    void rejectsTamperedCapsule() {
        RsaPreScheme scheme = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        UserKeyPair alice = scheme.generateKeyPair("alice");
        byte[] dataKey = SecureRandomUtil.randomBytes(32);
        EncryptedKeyCapsule original = scheme.encapsulate(dataKey, alice.publicKey());

        byte[] tamperedHeader = original.header().clone();
        tamperedHeader[tamperedHeader.length - 1] ^= 1;
        EncryptedKeyCapsule tampered = new EncryptedKeyCapsule(
                original.algorithm(),
                tamperedHeader,
                original.wrappedKey(),
                original.keyNonce()
        );

        assertThrows(RuntimeException.class, () -> scheme.decapsulate(tampered, alice.privateKey()));
    }
}
