package com.example.pre.crypto.provider;

public enum CryptoProfile {
    DEMO_RSA,
    DEMO_ECC,
    STANDARD_ENVELOPE,
    THRESHOLD_EXPERIMENTAL;

    public static CryptoProfile productionDefault() {
        return STANDARD_ENVELOPE;
    }
}
