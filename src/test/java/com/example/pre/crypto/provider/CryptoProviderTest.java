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
        CapsuleContext context = context("tenant-a", "data-1", "alice", "bob", "grant-1",
                "policy-1", 1, "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD");

        var capsule = provider.encapsulate(dek, bob.publicKey(), context);
        assertArrayEquals(dek, provider.decapsulate(capsule, bob.privateKey(), context));

        CapsuleContext[] tampered = {
                context("tenant-b", "data-1", "alice", "bob", "grant-1", "policy-1", 1, "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-2", "alice", "bob", "grant-1", "policy-1", 1, "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-1", "carol", "bob", "grant-1", "policy-1", 1, "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-1", "alice", "mallory", "grant-1", "policy-1", 1, "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-1", "alice", "bob", "grant-2", "policy-1", 1, "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-1", "alice", "bob", "grant-1", "policy-2", 1, "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-1", "alice", "bob", "grant-1", "policy-1", 2, "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-1", "alice", "bob", "grant-1", "policy-1", 1, "SECURE_ENVELOPE_V2", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-1", "alice", "bob", "grant-1", "policy-1", 1, "SECURE_ENVELOPE_V1", "proxy-b", "DOWNLOAD"),
                new CapsuleContext("data-1", "alice", "bob", AlgorithmType.SECURE_ENVELOPE, "owner-key-v2",
                        1, "policy-1", "tenant-a", "grant-1", "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                new CapsuleContext("data-1", "alice", "bob", AlgorithmType.RSA_PRE, "owner-key-v1",
                        1, "policy-1", "tenant-a", "grant-1", "SECURE_ENVELOPE_V1", "proxy-a", "DOWNLOAD"),
                context("tenant-a", "data-1", "alice", "bob", "grant-1", "policy-1", 1, "SECURE_ENVELOPE_V1", "proxy-a", "RE_ENCRYPT")
        };
        for (CapsuleContext changed : tampered) {
            assertThrows(IllegalArgumentException.class,
                    () -> provider.decapsulate(capsule, bob.privateKey(), changed));
        }
    }

    private static CapsuleContext context(String tenantId, String dataId, String ownerId, String recipientId,
                                          String grantId, String policyHash, int version, String suite,
                                          String proxyId, String operation) {
        return new CapsuleContext(dataId, ownerId, recipientId, AlgorithmType.SECURE_ENVELOPE, "owner-key-v1",
                version, policyHash, tenantId, grantId, suite, proxyId, operation);
    }

    @Test
    void registryDoesNotSelectBaselineForProductionDefault() {
        CryptoProviderRegistry registry = new CryptoProviderRegistry();
        assertFalse(registry.productionDefault().descriptor().baselineOnly());
        assertTrue(registry.require("RSA_PRE_BASELINE").descriptor().baselineOnly());
        assertTrue(registry.require("ECC_PRE_BASELINE").descriptor().baselineOnly());
    }
}
