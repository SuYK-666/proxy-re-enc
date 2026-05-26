package com.example.pre.crypto.provider;

import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoProviderTest {
    @Test
    void secureEnvelopeWrapsDekAndBindsContext() {
        SecureEnvelopeProvider provider = new SecureEnvelopeProvider();
        var bob = provider.generateKeyPair("bob");
        byte[] dek = SecureRandomUtil.randomBytes(32);
        CapsuleContext context = new CapsuleContext("data-1", "alice", "bob", AlgorithmType.SECURE_ENVELOPE,
                "owner-key-v1", 1, "policy-1");

        var capsule = provider.encapsulate(dek, bob.publicKey(), context);
        assertArrayEquals(dek, provider.decapsulate(capsule, bob.privateKey(), context));

        CapsuleContext tampered = new CapsuleContext("data-1", "alice", "bob", AlgorithmType.SECURE_ENVELOPE,
                "owner-key-v1", 1, "policy-tampered");
        assertThrows(IllegalArgumentException.class,
                () -> provider.decapsulate(capsule, bob.privateKey(), tampered));
    }

    @Test
    void registryDoesNotSelectBaselineForProductionDefault() {
        CryptoProviderRegistry registry = new CryptoProviderRegistry();
        assertFalse(registry.productionDefault().descriptor().baselineOnly());
        assertTrue(registry.require("RSA_PRE_BASELINE").descriptor().baselineOnly());
        assertTrue(registry.require("ECC_PRE_BASELINE").descriptor().baselineOnly());
    }
}
