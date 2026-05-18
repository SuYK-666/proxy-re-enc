package com.example.pre.crypto.ecc;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.kdf.Kdf;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.SecureRandomUtil;

import java.math.BigInteger;

public final class EccPreScheme implements PreScheme {
    private static final BigInteger ONE = BigInteger.ONE;
    private final P256Curve curve = new P256Curve();

    @Override
    public String name() {
        return "ECC-PRE";
    }

    @Override
    public UserKeyPair generateKeyPair(String userId) {
        BigInteger x = randomScalar();
        EccPoint publicPoint = curve.multiply(x, P256Curve.G);
        return new UserKeyPair(userId, new EccPublicKeyMaterial(publicPoint), new EccPrivateKeyMaterial(x));
    }

    @Override
    public EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial ownerPublicKey) {
        EccPublicKeyMaterial publicKey = expectPublic(ownerPublicKey);
        BigInteger r = randomScalar();
        EccPoint c1 = curve.multiply(r, P256Curve.G);
        EccPoint shared = curve.multiply(r, publicKey.point());
        byte[] kek = Kdf.sha256("ECC-PRE-KEM", curve.encode(shared));
        AesGcm.CipherText wrapped = AesGcm.encrypt(kek, dataKey, null);
        return new EncryptedKeyCapsule(
                AlgorithmType.ECC_PRE,
                curve.encode(c1),
                wrapped.ciphertext(),
                wrapped.nonce()
        );
    }

    @Override
    public byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey) {
        requireEccCapsule(capsule);
        EccPrivateKeyMaterial key = expectPrivate(privateKey);
        EccPoint c1 = curve.decode(capsule.header());
        EccPoint shared = curve.multiply(key.scalar(), c1);
        byte[] kek = Kdf.sha256("ECC-PRE-KEM", curve.encode(shared));
        return AesGcm.decrypt(kek, capsule.keyNonce(), capsule.wrappedKey(), null);
    }

    @Override
    public EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey) {
        requireEccCapsule(originalCapsule);
        if (!(reKey instanceof EccReEncryptionKey key)) {
            throw new IllegalArgumentException("expected ECC re-encryption key");
        }
        EccPoint c1 = curve.decode(originalCapsule.header());
        EccPoint transformed = curve.multiply(key.scalar(), c1);
        return new EncryptedKeyCapsule(
                AlgorithmType.ECC_PRE,
                curve.encode(transformed),
                originalCapsule.wrappedKey(),
                originalCapsule.keyNonce()
        );
    }

    public P256Curve curve() {
        return curve;
    }

    private static BigInteger randomScalar() {
        return SecureRandomUtil.randomInRange(ONE, P256Curve.N);
    }

    private static EccPublicKeyMaterial expectPublic(PublicKeyMaterial key) {
        if (!(key instanceof EccPublicKeyMaterial eccKey)) {
            throw new IllegalArgumentException("expected ECC public key");
        }
        return eccKey;
    }

    private static EccPrivateKeyMaterial expectPrivate(PrivateKeyMaterial key) {
        if (!(key instanceof EccPrivateKeyMaterial eccKey)) {
            throw new IllegalArgumentException("expected ECC private key");
        }
        return eccKey;
    }

    private static void requireEccCapsule(EncryptedKeyCapsule capsule) {
        if (capsule.algorithm() != AlgorithmType.ECC_PRE) {
            throw new IllegalArgumentException("expected ECC capsule");
        }
    }
}
