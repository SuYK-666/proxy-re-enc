package com.example.pre.crypto;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CapsuleContextBindingTest {
    @Test
    void rsaCapsuleBindsWrappedDekToContextAadAndKdf() {
        RsaPreScheme scheme = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        assertContextBinding(scheme, AlgorithmType.RSA_PRE);
    }

    @Test
    void eccCapsuleBindsWrappedDekToContextAadAndKdf() {
        EccPreScheme scheme = new EccPreScheme();
        assertContextBinding(scheme, AlgorithmType.ECC_PRE);
    }

    private static void assertContextBinding(PreScheme scheme, AlgorithmType algorithm) {
        UserKeyPair alice = scheme.generateKeyPair("alice");
        byte[] dataKey = SecureRandomUtil.randomBytes(32);
        CapsuleContext context = new CapsuleContext("data-1", "alice", "alice", algorithm, "key-1", 1, "policy-a");
        EncryptedKeyCapsule capsule = scheme.encapsulate(dataKey, alice.publicKey(), context);
        assertTrue(capsule.aadHash().length() >= 64);
        assertArrayEquals(dataKey, scheme.decapsulate(capsule, alice.privateKey(), context));

        CapsuleContext wrongData = new CapsuleContext("data-2", "alice", "alice", algorithm, "key-1", 1, "policy-a");
        assertThrows(IllegalArgumentException.class, () -> scheme.decapsulate(capsule, alice.privateKey(), wrongData));

        CapsuleContext wrongPolicy = new CapsuleContext("data-1", "alice", "alice", algorithm, "key-1", 1, "policy-b");
        assertThrows(IllegalArgumentException.class, () -> scheme.decapsulate(capsule, alice.privateKey(), wrongPolicy));
    }
}
