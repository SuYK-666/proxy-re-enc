package com.example.pre.crypto;

import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmTest {
    @Test
    void decryptsOriginalPlaintextAndRejectsTampering() {
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] aad = Bytes.utf8("data-id|owner");
        byte[] plaintext = Bytes.utf8("hello encrypted world");

        AesGcm.CipherText cipherText = AesGcm.encrypt(key, plaintext, aad);
        assertArrayEquals(plaintext, AesGcm.decrypt(key, cipherText.nonce(), cipherText.ciphertext(), aad));

        byte[] tampered = cipherText.ciphertext().clone();
        tampered[0] ^= 1;
        assertThrows(IllegalArgumentException.class,
                () -> AesGcm.decrypt(key, cipherText.nonce(), tampered, aad));
    }
}
