package com.example.pre.crypto.rsa;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.kdf.Kdf;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;

import java.math.BigInteger;

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
                new RsaPrivateKeyMaterial(parameters.modulus(), d, phi)
        );
    }

    @Override
    public EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial ownerPublicKey) {
        RsaPublicKeyMaterial publicKey = expectPublic(ownerPublicKey);
        BigInteger s = randomUnit();
        BigInteger c = s.modPow(publicKey.exponent(), publicKey.modulus());
        byte[] secret = Bytes.unsignedFixed(s, parameters.modulusBytes());
        byte[] kek = Kdf.sha256("RSA-PRE-KEM", secret);
        AesGcm.CipherText wrapped = AesGcm.encrypt(kek, dataKey, null);
        return new EncryptedKeyCapsule(
                AlgorithmType.RSA_PRE,
                Bytes.unsignedFixed(c, parameters.modulusBytes()),
                wrapped.ciphertext(),
                wrapped.nonce()
        );
    }

    @Override
    public byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey) {
        requireRsaCapsule(capsule);
        RsaPrivateKeyMaterial key = expectPrivate(privateKey);
        BigInteger c = Bytes.positiveBigInteger(capsule.header());
        BigInteger s = c.modPow(key.privateExponent(), key.modulus());
        byte[] secret = Bytes.unsignedFixed(s, parameters.modulusBytes());
        byte[] kek = Kdf.sha256("RSA-PRE-KEM", secret);
        return AesGcm.decrypt(kek, capsule.keyNonce(), capsule.wrappedKey(), null);
    }

    @Override
    public EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey) {
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
        );
    }

    public RsaCommonModulusParameters parameters() {
        return parameters;
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
}
