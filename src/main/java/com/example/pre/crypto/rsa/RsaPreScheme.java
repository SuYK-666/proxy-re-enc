package com.example.pre.crypto.rsa;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.kdf.Kdf;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.UserKeyPair;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.util.AadBuilder;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;

import java.math.BigInteger;
import java.util.Arrays;

public final class RsaPreScheme implements PreScheme {
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private final RsaCommonModulusParameters parameters;

    public RsaPreScheme(RsaCommonModulusParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public String name() {
        return "RSA-PRE";
    }

    @Override
    public String parameterSpec() {
        return "RSA-PRE-demo-common-modulus-" + parameters.modulus().bitLength();
    }

    @Override
    public UserKeyPair generateKeyPair(String userId) {
        BigInteger phi = parameters.phi();
        BigInteger h = parameters.sharedExponentFactor();
        BigInteger t;
        BigInteger e;
        do {
            t = BigInteger.probablePrime(160, SecureRandomUtil.random());
            e = h.multiply(t);
        } while (!t.gcd(phi).equals(BigInteger.ONE) || !e.gcd(phi).equals(BigInteger.ONE));
        BigInteger d = e.modInverse(phi);
        return new UserKeyPair(
                userId,
                new RsaPublicKeyMaterial(parameters.modulus(), e),
                new RsaPrivateKeyMaterial(parameters.modulus(), d)
        );
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
        RsaPublicKeyMaterial publicKey = expectPublic(ownerPublicKey);
        BigInteger s = randomUnit();
        BigInteger c = s.modPow(publicKey.exponent(), publicKey.modulus());
        byte[] secret = Bytes.unsignedFixed(s, parameters.modulusBytes());
        byte[] aad = aad(context);
        byte[] kek = Kdf.sha256(kdfLabel(context), secret);
        try {
            AesGcm.CipherText wrapped = AesGcm.encrypt(kek, dataKey, aad);
            return new EncryptedKeyCapsule(
                    AlgorithmType.RSA_PRE,
                    Bytes.unsignedFixed(c, parameters.modulusBytes()),
                    wrapped.ciphertext(),
                    wrapped.nonce()
            ).bindContext(context == null ? "" : context.ownerKeyId(), 1, hash(aad), hash(aad), parameterSpec());
        } finally {
            Arrays.fill(secret, (byte) 0);
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
        requireRsaCapsule(capsule);
        RsaPrivateKeyMaterial key = expectPrivate(privateKey);
        BigInteger c = Bytes.positiveBigInteger(capsule.header());
        BigInteger s = c.modPow(key.privateExponent(), key.modulus());
        byte[] secret = Bytes.unsignedFixed(s, parameters.modulusBytes());
        byte[] aad = aad(context);
        byte[] kek = Kdf.sha256(kdfLabel(context), secret);
        try {
            return AesGcm.decrypt(kek, capsule.keyNonce(), capsule.wrappedKey(), aad);
        } finally {
            Arrays.fill(secret, (byte) 0);
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
        requireRsaCapsule(originalCapsule);
        if (!(reKey instanceof RsaReEncryptionKey key)) {
            throw new IllegalArgumentException("expected RSA re-encryption key");
        }
        BigInteger c = Bytes.positiveBigInteger(originalCapsule.header());
        BigInteger transformed = c.modPow(key.exponent(), key.modulus());
        return new EncryptedKeyCapsule(
                AlgorithmType.RSA_PRE,
                Bytes.unsignedFixed(transformed, parameters.modulusBytes()),
                originalCapsule.wrappedKey(),
                originalCapsule.keyNonce()
        ).bindContext(originalCapsule.ownerKeyId(), originalCapsule.ownerKeyVersion(), originalCapsule.aadHash(),
                originalCapsule.contextHash(), originalCapsule.parameterSpec());
    }

    public RsaCommonModulusParameters parameters() {
        return parameters;
    }

    public ReEncryptionKey generateBaselineReEncryptionKey(
            RsaPrivateKeyMaterial ownerPrivateKey,
            RsaPublicKeyMaterial recipientPublicKey
    ) {
        return new RsaReKeyGenerator().generateReEncryptionKey(ownerPrivateKey, recipientPublicKey, parameters.phi());
    }

    private BigInteger randomUnit() {
        BigInteger n = parameters.modulus();
        BigInteger s;
        do {
            s = SecureRandomUtil.randomInRange(TWO, n);
        } while (!s.gcd(n).equals(BigInteger.ONE));
        return s;
    }

    private static RsaPublicKeyMaterial expectPublic(PublicKeyMaterial key) {
        if (!(key instanceof RsaPublicKeyMaterial rsaKey)) {
            throw new IllegalArgumentException("expected RSA public key");
        }
        return rsaKey;
    }

    private static RsaPrivateKeyMaterial expectPrivate(PrivateKeyMaterial key) {
        if (!(key instanceof RsaPrivateKeyMaterial rsaKey)) {
            throw new IllegalArgumentException("expected RSA private key");
        }
        return rsaKey;
    }

    private static void requireRsaCapsule(EncryptedKeyCapsule capsule) {
        if (capsule.algorithm() != AlgorithmType.RSA_PRE) {
            throw new IllegalArgumentException("expected RSA capsule");
        }
    }

    @Override
    public void validateCapsule(EncryptedKeyCapsule capsule, CapsuleContext context) {
        requireRsaCapsule(capsule);
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
                ? "ReKeyShare|RSA-PRE|DEK-WRAP|v1"
                : "ReKeyShare|RSA-PRE|DEK-WRAP|v1|" + AadBuilder.buildString(context);
    }

    private static String hash(byte[] aad) {
        return aad == null ? "" : Hash.sha256Hex(aad);
    }
}
