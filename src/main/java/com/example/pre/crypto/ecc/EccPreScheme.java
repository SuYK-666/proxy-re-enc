package com.example.pre.crypto.ecc;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.kdf.Kdf;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.AadBuilder;
import com.example.pre.util.SecureRandomUtil;

import java.math.BigInteger;
import java.util.Arrays;

public final class EccPreScheme implements PreScheme {
    private static final BigInteger ONE = BigInteger.ONE;
    private final P256Curve curve = new P256Curve();

    @Override
    public String name() {
        return "ECC-PRE";
    }

    @Override
    public String parameterSpec() {
        return "ECC-PRE-P-256-demo";
    }

    @Override
    public UserKeyPair generateKeyPair(String userId) {
        BigInteger x = randomScalar();
        EccPoint publicPoint = curve.multiply(x, P256Curve.G);
        return new UserKeyPair(userId, new EccPublicKeyMaterial(publicPoint), new EccPrivateKeyMaterial(x));
    }

    @Override
    public EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial ownerPublicKey) {
        return encapsulateInternal(dataKey, ownerPublicKey, null);
    }

    @Override
    public EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial ownerPublicKey, CapsuleContext context) {
        return encapsulateInternal(dataKey, ownerPublicKey, context);
    }

    private EncryptedKeyCapsule encapsulateInternal(byte[] dataKey, PublicKeyMaterial ownerPublicKey, CapsuleContext context) {
        EccPublicKeyMaterial publicKey = expectPublic(ownerPublicKey);
        BigInteger r = randomScalar();
        EccPoint c1 = curve.multiply(r, P256Curve.G);
        EccPoint shared = curve.multiply(r, publicKey.point());
        byte[] aad = aad(context);
        byte[] sharedSecret = curve.encode(shared);
        byte[] kek = Kdf.sha256(kdfLabel(context), sharedSecret);
        try {
            AesGcm.CipherText wrapped = AesGcm.encrypt(kek, dataKey, aad);
            return new EncryptedKeyCapsule(
                    AlgorithmType.ECC_PRE,
                    curve.encode(c1),
                    wrapped.ciphertext(),
                    wrapped.nonce()
            ).bindContext(context == null ? "" : context.ownerKeyId(), 1, hash(aad), hash(aad), parameterSpec());
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            Arrays.fill(kek, (byte) 0);
        }
    }

    @Override
    public byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey) {
        return decapsulateInternal(capsule, privateKey, null);
    }

    @Override
    public byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey, CapsuleContext context) {
        validateCapsule(capsule, context);
        return decapsulateInternal(capsule, privateKey, context);
    }

    private byte[] decapsulateInternal(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey, CapsuleContext context) {
        requireEccCapsule(capsule);
        EccPrivateKeyMaterial key = expectPrivate(privateKey);
        EccPoint c1 = curve.decode(capsule.header());
        EccPoint shared = curve.multiply(key.scalar(), c1);
        byte[] aad = aad(context);
        byte[] sharedSecret = curve.encode(shared);
        byte[] kek = Kdf.sha256(kdfLabel(context), sharedSecret);
        try {
            return AesGcm.decrypt(kek, capsule.keyNonce(), capsule.wrappedKey(), aad);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            Arrays.fill(kek, (byte) 0);
        }
    }

    @Override
    public EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey) {
        return reEncryptInternal(originalCapsule, reKey);
    }

    @Override
    public EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey, CapsuleContext context) {
        validateCapsule(originalCapsule, context);
        return reEncryptInternal(originalCapsule, reKey);
    }

    private EncryptedKeyCapsule reEncryptInternal(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey) {
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
        ).bindContext(originalCapsule.ownerKeyId(), originalCapsule.ownerKeyVersion(), originalCapsule.aadHash(),
                originalCapsule.contextHash(), originalCapsule.parameterSpec());
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

    @Override
    public void validateCapsule(EncryptedKeyCapsule capsule, CapsuleContext context) {
        requireEccCapsule(capsule);
        byte[] aad = aad(context);
        String expected = hash(aad);
        if (context != null && !capsule.aadHash().isBlank() && !expected.equals(capsule.aadHash())) {
            throw new IllegalArgumentException("capsule AAD hash mismatch");
        }
    }

    private static byte[] aad(CapsuleContext context) {
        return context == null ? null : AadBuilder.build(context);
    }

    private static String kdfLabel(CapsuleContext context) {
        return context == null
                ? "ReKeyShare|ECC-PRE|DEK-WRAP|v1"
                : "ReKeyShare|ECC-PRE|DEK-WRAP|v1|" + AadBuilder.buildString(context);
    }

    private static String hash(byte[] aad) {
        return aad == null ? "" : Hash.sha256Hex(aad);
    }
}
