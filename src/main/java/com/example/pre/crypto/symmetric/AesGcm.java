package com.example.pre.crypto.symmetric;

import com.example.pre.util.SecureRandomUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public final class AesGcm {
    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private AesGcm() {
    }

    public record CipherText(byte[] nonce, byte[] ciphertext) {
    }

    public static CipherText encrypt(byte[] key, byte[] plaintext, byte[] aad) {
        byte[] nonce = SecureRandomUtil.randomBytes(NONCE_BYTES);
        return new CipherText(nonce, crypt(Cipher.ENCRYPT_MODE, key, nonce, plaintext, aad));
    }

    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
        return crypt(Cipher.DECRYPT_MODE, key, nonce, ciphertext, aad);
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] input, byte[] aad) {
        if (key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES-GCM key must be 32 bytes");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("AES-GCM operation failed", e);
        }
    }
}
