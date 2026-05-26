package com.example.pre.util;

import org.junit.jupiter.api.Test;

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
}
