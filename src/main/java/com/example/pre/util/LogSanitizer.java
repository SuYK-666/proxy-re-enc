package com.example.pre.util;

import java.util.regex.Pattern;

public final class LogSanitizer {
    private static final Pattern[] SENSITIVE_PATTERNS = {
            Pattern.compile("(?i)(authorization|token|privateKey|dek|plaintext|rekeySecret)\\s*[:=]\\s*[^,\\s}]+"),
            Pattern.compile("(?i)(Bearer)\\s+[A-Za-z0-9._-]+")
    };

    private LogSanitizer() {
    }

    public static String sanitize(String value) {
        String sanitized = value == null ? "" : value;
        for (Pattern pattern : SENSITIVE_PATTERNS) {
            sanitized = pattern.matcher(sanitized).replaceAll("$1=<redacted>");
        }
        return sanitized;
    }
}
