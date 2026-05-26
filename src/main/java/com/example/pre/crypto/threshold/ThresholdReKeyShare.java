package com.example.pre.crypto.threshold;

public record ThresholdReKeyShare(int threshold, int totalShares, int index, byte[] value) {
    public ThresholdReKeyShare {
        if (threshold < 2 || totalShares < threshold || index < 1 || index > totalShares) {
            throw new IllegalArgumentException("invalid threshold share metadata");
        }
        value = value.clone();
    }

    @Override
    public byte[] value() {
        return value.clone();
    }
}
