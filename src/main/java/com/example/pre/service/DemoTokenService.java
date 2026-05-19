package com.example.pre.service;

import com.example.pre.model.User;
import com.example.pre.model.UserRole;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class DemoTokenService {
    private static final String HMAC = "HmacSHA256";
    private final Map<String, byte[]> secrets = new ConcurrentHashMap<>();
    private final Set<String> revokedTokenIds = ConcurrentHashMap.newKeySet();
    private final long ttlSeconds;
    private final String issuer;
    private final String audience;
    private volatile String activeKeyId;

    public record AuthenticatedActor(String userId, UserRole role, String tenantId, String tokenId, long issuedAt, long expiresAt) {
        public SecurityContext securityContext() {
            return new SecurityContext(userId, role, tenantId, tokenId, issuedAt, expiresAt);
        }
    }

    public DemoTokenService(String secret, long ttlSeconds) {
        this(secret, ttlSeconds, "rekeyshare-demo-issuer", "rekeyshare-api", "demo-kid-1");
    }

    public DemoTokenService(String secret, long ttlSeconds, String issuer, String audience, String keyId) {
        this.secrets.put(keyId, secret.getBytes(StandardCharsets.UTF_8));
        this.ttlSeconds = ttlSeconds;
        this.issuer = issuer;
        this.audience = audience;
        this.activeKeyId = keyId;
    }

    public String issue(User user) {
        long issuedAt = Instant.now().getEpochSecond();
        long expiresAt = issuedAt + ttlSeconds;
        String tokenId = UUID.randomUUID().toString();
        String payload = user.userId() + "|" + user.role().name() + "|" + issuedAt + "|"
                + expiresAt + "|" + tokenId + "|default|" + issuer + "|" + audience + "|" + activeKeyId;
        return base64(payload) + "." + sign(payload);
    }

    public void rotateSigningKey(String keyId, String secret) {
        secrets.put(keyId, secret.getBytes(StandardCharsets.UTF_8));
        activeKeyId = keyId;
    }

    public void revoke(String tokenId) {
        revokedTokenIds.add(tokenId);
    }

    public AuthenticatedActor verify(String token) {
        if (token == null || token.isBlank()) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "missing bearer token");
        }
        String[] parts = token.split("\\.", 2);
        if (parts.length != 2) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "invalid bearer token");
        }
        String payload;
        try {
            payload = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "invalid token encoding");
        }
        if (!MessageDigest.isEqual(sign(payload).getBytes(StandardCharsets.UTF_8), parts[1].getBytes(StandardCharsets.UTF_8))) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "invalid token signature");
        }
        String[] fields = payload.split("\\|", 9);
        if (fields.length != 9) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "invalid token payload");
        }
        long issuedAt = parseEpoch(fields[2]);
        long expiresAt = parseEpoch(fields[3]);
        String tokenId = fields[4];
        if (revokedTokenIds.contains(tokenId)) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "token revoked");
        }
        if (!issuer.equals(fields[6]) || !audience.equals(fields[7])) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "token issuer or audience mismatch");
        }
        if (issuedAt > Instant.now().getEpochSecond() + 60) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "token issued in the future");
        }
        if (expiresAt <= Instant.now().getEpochSecond()) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "token expired");
        }
        return new AuthenticatedActor(fields[0], UserRole.valueOf(fields[1]), fields[5], tokenId, issuedAt, expiresAt);
    }

    private String sign(String payload) {
        try {
            String[] fields = payload.split("\\|", 9);
            String keyId = fields.length == 9 ? fields[8] : activeKeyId;
            byte[] secret = secrets.get(keyId);
            if (secret == null) {
                throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "unknown token key id");
            }
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(secret, HMAC));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "token signing failed");
        }
    }

    private static long parseEpoch(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "invalid token time");
        }
    }

    private static String base64(String payload) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    }
}
