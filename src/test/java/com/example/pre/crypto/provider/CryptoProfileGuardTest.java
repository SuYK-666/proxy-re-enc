package com.example.pre.crypto.provider;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoProfileGuardTest {
    private final CryptoProviderRegistry registry = new CryptoProviderRegistry();

    @Test
    void standardProfileAllowsOnlySecureEnvelope() {
        assertDoesNotThrow(() -> registry.require(CryptoProfile.STANDARD_ENVELOPE, "SECURE_ENVELOPE_V1"));
        IllegalArgumentException rsa = assertThrows(IllegalArgumentException.class,
                () -> registry.require(CryptoProfile.STANDARD_ENVELOPE, "RSA_PRE_BASELINE"));
        IllegalArgumentException ecc = assertThrows(IllegalArgumentException.class,
                () -> registry.require(CryptoProfile.STANDARD_ENVELOPE, "ECC_PRE_BASELINE"));
        assertTrue(rsa.getMessage().contains("CRYPTO_PROFILE_NOT_ALLOWED"));
        assertTrue(ecc.getMessage().contains("CRYPTO_PROFILE_NOT_ALLOWED"));
    }

    @Test
    void demoProfilesCannotSelectProductionOrAnotherBaseline() {
        assertDoesNotThrow(() -> registry.require(CryptoProfile.DEMO_RSA, "RSA_PRE_BASELINE"));
        assertDoesNotThrow(() -> registry.require(CryptoProfile.DEMO_ECC, "ECC_PRE_BASELINE"));
        assertThrows(IllegalArgumentException.class,
                () -> registry.require(CryptoProfile.DEMO_RSA, "SECURE_ENVELOPE_V1"));
        assertThrows(IllegalArgumentException.class,
                () -> registry.require(CryptoProfile.DEMO_ECC, "RSA_PRE_BASELINE"));
    }
}
