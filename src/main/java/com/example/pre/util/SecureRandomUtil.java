package com.example.pre.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class SecureRandomUtil {
    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureRandomUtil() {
    }

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    public static BigInteger randomInRange(BigInteger minInclusive, BigInteger maxExclusive) {
        BigInteger span = maxExclusive.subtract(minInclusive);
        BigInteger candidate;
        do {
            candidate = new BigInteger(span.bitLength(), RANDOM);
        } while (candidate.compareTo(span) >= 0);
        return candidate.add(minInclusive);
    }

    public static SecureRandom random() {
        return RANDOM;
    }
}
