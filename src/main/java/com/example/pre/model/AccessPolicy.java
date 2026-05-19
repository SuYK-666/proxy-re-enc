package com.example.pre.model;

import java.time.Instant;

public record AccessPolicy(
        boolean allowPreview,
        boolean allowDownload,
        boolean allowReshare,
        int maxAccessCount,
        int maxReEncryptCount,
        int maxDownloadCount,
        int maxDecryptCount,
        Instant expiresAt,
        String purpose,
        String allowedActions
) {
    public AccessPolicy {
        if (maxAccessCount < 1) {
            throw new IllegalArgumentException("maxAccessCount must be positive");
        }
        if (maxReEncryptCount < 1 || maxDownloadCount < 1 || maxDecryptCount < 1) {
            throw new IllegalArgumentException("per-action limits must be positive");
        }
        purpose = purpose == null ? "" : purpose;
        allowedActions = allowedActions == null ? "download,decrypt" : allowedActions;
    }

    public AccessPolicy(
            boolean allowPreview,
            boolean allowDownload,
            boolean allowReshare,
            int maxAccessCount,
            Instant expiresAt,
            String purpose
    ) {
        this(
                allowPreview,
                allowDownload,
                allowReshare,
                maxAccessCount,
                maxAccessCount,
                maxAccessCount,
                maxAccessCount,
                expiresAt,
                purpose,
                "download,decrypt"
        );
    }

    public static AccessPolicy normal(Instant expiresAt) {
        return new AccessPolicy(true, true, false, 10, expiresAt, "course-demo");
    }

    public boolean expired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    public String canonicalJson() {
        return "{"
                + "\"allowDownload\":" + allowDownload + ","
                + "\"allowPreview\":" + allowPreview + ","
                + "\"allowReshare\":" + allowReshare + ","
                + "\"expiresAt\":\"" + (expiresAt == null ? "" : expiresAt) + "\","
                + "\"maxDecryptCount\":" + maxDecryptCount + ","
                + "\"maxDownloadCount\":" + maxDownloadCount + ","
                + "\"maxAccessCount\":" + maxAccessCount + ","
                + "\"maxReEncryptCount\":" + maxReEncryptCount + ","
                + "\"purpose\":\"" + escape(purpose) + "\","
                + "\"allowedActions\":\"" + escape(allowedActions) + "\""
                + "}";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
