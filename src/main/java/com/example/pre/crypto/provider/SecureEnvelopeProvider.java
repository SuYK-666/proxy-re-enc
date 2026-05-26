package com.example.pre.crypto.provider;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.envelope.SecureEnvelopePrivateKey;
import com.example.pre.crypto.envelope.SecureEnvelopePublicKey;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.crypto.kdf.Kdf;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.AadBuilder;
import com.example.pre.util.Bytes;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Direct recipient envelope path based on JCA P-256 ECDH, HKDF-SHA256 and AES-256-GCM.
 * It deliberately does not claim proxy transformation semantics.
 */
public final class SecureEnvelopeProvider implements CryptoProvider {
    private static final byte[] INFO_PREFIX = Bytes.utf8("ReKeyShare|SECURE_ENVELOPE|P256-HKDF-AESGCM|v1|");

    @Override
    public SchemeDescriptor descriptor() {
        return new SchemeDescriptor("SECURE_ENVELOPE_V1", "ECDH-KEM envelope", "128-bit",
                "P-256/HKDF-SHA256/AES-256-GCM", false, false, false,
                "JCA_PRIMITIVES_SECURITY_BOUNDARY_DOCUMENTED", "IMPLEMENTED");
    }

    @Override
    public UserKeyPair generateKeyPair(String userId) {
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            var keyPair = generator.generateKeyPair();
            return new UserKeyPair(userId, new SecureEnvelopePublicKey(keyPair.getPublic().getEncoded()),
                    new SecureEnvelopePrivateKey(keyPair.getPrivate().getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 is unavailable", e);
        }
    }

    @Override
    public EncryptedKeyCapsule encapsulate(byte[] dek, PublicKeyMaterial recipient, CapsuleContext context) {
        if (!(recipient instanceof SecureEnvelopePublicKey publicKey)) {
            throw new IllegalArgumentException("expected secure envelope public key");
        }
        byte[] aad = aad(context);
        try {
            var ephemeral = generateEphemeral();
            byte[] kek = derive(ephemeral.getPrivate(), decodePublic(publicKey.encoded()), aad);
            try {
                AesGcm.CipherText wrapped = AesGcm.encrypt(kek, dek, aad);
                return new EncryptedKeyCapsule(AlgorithmType.SECURE_ENVELOPE, ephemeral.getPublic().getEncoded(),
                        wrapped.ciphertext(), wrapped.nonce()).bindContext(
                        context == null ? "" : context.ownerKeyId(),
                        context == null ? 1 : context.contentKeyVersion(),
                        hash(aad), hash(aad), descriptor().parameterSpec());
            } finally {
                Arrays.fill(kek, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("secure envelope encapsulation failed", e);
        }
    }

    @Override
    public EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule capsule, ReEncryptionKey reKey, CapsuleContext context) {
        throw new UnsupportedOperationException("secure envelope is direct-recipient wrapping, not proxy transformation");
    }

    @Override
    public byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial recipientPrivateKey, CapsuleContext context) {
        if (capsule.algorithm() != AlgorithmType.SECURE_ENVELOPE) {
            throw new IllegalArgumentException("expected secure envelope capsule");
        }
        if (!(recipientPrivateKey instanceof SecureEnvelopePrivateKey privateKey)) {
            throw new IllegalArgumentException("expected secure envelope private key");
        }
        byte[] aad = aad(context);
        if (context != null && !hash(aad).equals(capsule.aadHash())) {
            throw new IllegalArgumentException("secure envelope AAD mismatch");
        }
        try {
            byte[] kek = derive(decodePrivate(privateKey.encoded()), decodePublic(capsule.header()), aad);
            try {
                return AesGcm.decrypt(kek, capsule.keyNonce(), capsule.wrappedKey(), aad);
            } finally {
                Arrays.fill(kek, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("secure envelope decapsulation failed", e);
        }
    }

    private static java.security.KeyPair generateEphemeral() throws GeneralSecurityException {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static byte[] derive(PrivateKey privateKey, PublicKey publicKey, byte[] aad) throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        byte[] shared = agreement.generateSecret();
        try {
            return Kdf.hkdfSha256(null, shared, Bytes.concat(INFO_PREFIX, aad), AesGcm.KEY_BYTES);
        } finally {
            Arrays.fill(shared, (byte) 0);
        }
    }

    private static PublicKey decodePublic(byte[] encoded) throws GeneralSecurityException {
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static PrivateKey decodePrivate(byte[] encoded) throws GeneralSecurityException {
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private static byte[] aad(CapsuleContext context) {
        return context == null ? new byte[0] : AadBuilder.build(context);
    }

    private static String hash(byte[] aad) {
        return Hash.sha256Hex(aad);
    }
}
