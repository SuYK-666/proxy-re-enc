package com.example.pre.crypto;

import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmAdditionalTest {
    @Test
    void encryptingSamePlaintextUsesDifferentNonceAndCiphertext() {
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] plaintext = Bytes.utf8("same plaintext");
        AesGcm.CipherText first = AesGcm.encrypt(key, plaintext, Bytes.utf8("aad"));
        AesGcm.CipherText second = AesGcm.encrypt(key, plaintext, Bytes.utf8("aad"));
        assertFalse(Arrays.equals(first.nonce(), second.nonce()));
        assertFalse(Arrays.equals(first.ciphertext(), second.ciphertext()));
    }

    @Test
    void rejectsWrongAadWrongNonceAndWrongKey() {
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] plaintext = Bytes.utf8("authenticated data");
        AesGcm.CipherText cipherText = AesGcm.encrypt(key, plaintext, Bytes.utf8("aad-1"));
        assertArrayEquals(plaintext, AesGcm.decrypt(key, cipherText.nonce(), cipherText.ciphertext(), Bytes.utf8("aad-1")));

        assertThrows(IllegalArgumentException.class,
                () -> AesGcm.decrypt(key, cipherText.nonce(), cipherText.ciphertext(), Bytes.utf8("aad-2")));

        byte[] wrongNonce = cipherText.nonce().clone();
        wrongNonce[0] ^= 1;
        assertThrows(IllegalArgumentException.class,
                () -> AesGcm.decrypt(key, wrongNonce, cipherText.ciphertext(), Bytes.utf8("aad-1")));

        byte[] wrongKey = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        assertThrows(IllegalArgumentException.class,
                () -> AesGcm.decrypt(wrongKey, cipherText.nonce(), cipherText.ciphertext(), Bytes.utf8("aad-1")));
    }

    @Test
    void rejectsTagTamperingAtEndOfCiphertext() {
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        AesGcm.CipherText cipherText = AesGcm.encrypt(key, Bytes.utf8("tag protected"), null);
        byte[] tampered = cipherText.ciphertext().clone();
        tampered[tampered.length - 1] ^= 1;
        assertThrows(IllegalArgumentException.class,
                () -> AesGcm.decrypt(key, cipherText.nonce(), tampered, null));
    }
}
