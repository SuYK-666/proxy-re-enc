package com.example.pre.crypto.provider;

public final class CryptoProfileGuard {
    private CryptoProfileGuard() {
    }

    public static void assertAllowed(CryptoProfile profile, SchemeDescriptor scheme) {
        boolean allowed = switch (profile) {
            case DEMO_RSA -> "RSA_PRE_BASELINE".equals(scheme.schemeId());
            case DEMO_ECC -> "ECC_PRE_BASELINE".equals(scheme.schemeId());
            case STANDARD_ENVELOPE -> "SECURE_ENVELOPE_V1".equals(scheme.schemeId())
                    && scheme.allowedAsProductionDefault();
            case THRESHOLD_EXPERIMENTAL -> scheme.supportsThreshold();
        };
        if (!allowed) {
            throw new IllegalArgumentException("CRYPTO_PROFILE_NOT_ALLOWED: scheme " + scheme.schemeId()
                    + " is not enabled for " + profile);
        }
    }
}
