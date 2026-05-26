package com.example.pre.util;

import com.example.pre.crypto.ecc.EccPrivateKeyMaterial;
import com.example.pre.crypto.ecc.EccReEncryptionKey;
import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.crypto.envelope.SecureEnvelopePrivateKey;
import com.example.pre.crypto.rsa.RsaPrivateKeyMaterial;
import com.example.pre.crypto.rsa.RsaReEncryptionKey;
import com.example.pre.crypto.threshold.ThresholdReKeyShare;
import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.model.AlgorithmType;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogSanitizerTest {
    @Test
    void removesSecretsAndBearerValuesFromOperationalMessages() {
        String value = LogSanitizer.sanitize("plaintext=medical dek=secret privateKey=pk Authorization=token Bearer abc.def");
        assertFalse(value.contains("medical"));
        assertFalse(value.contains("secret"));
        assertFalse(value.contains("abc.def"));
        assertTrue(value.contains("<redacted>"));
    }

    @Test
    void secretBearingValueObjectsDoNotExposeMaterialThroughToString() {
        String marker = "987654321";
        BigInteger secret = new BigInteger(marker);
        String output = new RsaPrivateKeyMaterial(BigInteger.TEN, secret)
                + new EccPrivateKeyMaterial(secret).toString()
                + new RsaReEncryptionKey(BigInteger.TEN, secret)
                + new EccReEncryptionKey(secret)
                + new RecipientReKeyShare(secret)
                + new SecureEnvelopePrivateKey(marker.getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                + new ThresholdReKeyShare(2, 3, 1, marker.getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                + new EncryptedKeyCapsule(AlgorithmType.RSA_PRE,
                        marker.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                        marker.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                        marker.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        assertFalse(output.contains(marker));
        assertTrue(output.contains("<redacted>"));
    }
}
