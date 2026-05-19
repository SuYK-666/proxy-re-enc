package com.example.pre.crypto.symmetric;

import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AesGcmNonceManagerTest {
    @Test
    void rejectsNonceReuseForSameKey() {
        AesGcmNonceManager.clearForTest();
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] nonce = SecureRandomUtil.randomBytes(AesGcm.NONCE_BYTES);

        assertTrue(AesGcmNonceManager.reserve(key, nonce));
        assertFalse(AesGcmNonceManager.reserve(key, nonce));
    }
}
