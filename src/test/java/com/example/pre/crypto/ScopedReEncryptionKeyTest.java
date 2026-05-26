package com.example.pre.crypto;

import com.example.pre.crypto.rsa.RsaReEncryptionKey;
import com.example.pre.model.AlgorithmType;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ScopedReEncryptionKeyTest {
    @Test
    void rejectsCrossScopeAndAtomicallyEnforcesUseLimit() {
        ScopedReEncryptionKey key = new ScopedReEncryptionKey(new RsaReEncryptionKey(BigInteger.TEN, BigInteger.TWO),
                "grant-1", "data-1", "bob", 2, "policy", Instant.now().plusSeconds(30), 1);
        assertEquals(AlgorithmType.RSA_PRE,
                key.consume("grant-1", "data-1", "bob", 2, "policy", Instant.now()).algorithm());
        assertEquals(1, key.usageCount());
        assertThrows(IllegalArgumentException.class,
                () -> key.consume("grant-1", "data-1", "bob", 2, "policy", Instant.now()));
        assertThrows(IllegalArgumentException.class,
                () -> new ScopedReEncryptionKey(new RsaReEncryptionKey(BigInteger.TEN, BigInteger.TWO),
                        "grant-1", "data-1", "bob", 2, "policy", Instant.now().plusSeconds(30), 2)
                        .consume("other-grant", "data-1", "bob", 2, "policy", Instant.now()));
    }
}
