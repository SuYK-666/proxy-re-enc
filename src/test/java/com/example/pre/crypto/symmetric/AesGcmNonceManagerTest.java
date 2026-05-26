package com.example.pre.crypto.symmetric;

import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AesGcmNonceManagerTest {
    @Test
    void rejectsNonceReuseForSameKey() {
        AesGcmNonceManager.clearForTest();
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] nonce = SecureRandomUtil.randomBytes(AesGcm.NONCE_BYTES);

        assertTrue(AesGcmNonceManager.reserve(key, nonce));
        assertFalse(AesGcmNonceManager.reserve(key, nonce));
    }

    @Test
    void rejectsPersistedNonceAfterMemoryRestart() {
        AesGcmNonceManager.clearForTest();
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] nonce = SecureRandomUtil.randomBytes(AesGcm.NONCE_BYTES);
        assertTrue(AesGcmNonceManager.reserve(key, nonce));
        AesGcmNonceManager.clearMemoryForRestartTest();
        assertFalse(AesGcmNonceManager.reserve(key, nonce));
    }

    @Test
    void allowsOnlyOneConcurrentReservationOfSameNonce() throws Exception {
        AesGcmNonceManager.clearForTest();
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] nonce = SecureRandomUtil.randomBytes(AesGcm.NONCE_BYTES);
        var executor = java.util.concurrent.Executors.newFixedThreadPool(100);
        try {
            java.util.List<java.util.concurrent.Future<Boolean>> futures = new java.util.ArrayList<>();
            for (int index = 0; index < 100; index++) {
                futures.add(executor.submit(() -> AesGcmNonceManager.reserve(key, nonce)));
            }
            int accepted = 0;
            for (var result : futures) {
                if (result.get()) {
                    accepted++;
                }
            }
            assertEquals(1, accepted);
        } finally {
            executor.shutdownNow();
        }
    }
}
