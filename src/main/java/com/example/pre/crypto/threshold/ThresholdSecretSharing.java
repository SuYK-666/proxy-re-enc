package com.example.pre.crypto.threshold;

import com.example.pre.util.SecureRandomUtil;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Experimental Shamir sharing over GF(256) for re-key material orchestration tests.
 * This is not a reviewed threshold PRE protocol.
 */
public final class ThresholdSecretSharing {
    private ThresholdSecretSharing() {
    }

    public static List<ThresholdReKeyShare> split(byte[] secret, int threshold, int totalShares) {
        if (secret.length == 0 || threshold < 2 || totalShares < threshold || totalShares > 255) {
            throw new IllegalArgumentException("invalid threshold split parameters");
        }
        byte[][] output = new byte[totalShares][secret.length];
        for (int offset = 0; offset < secret.length; offset++) {
            byte[] coefficients = SecureRandomUtil.randomBytes(threshold);
            coefficients[0] = secret[offset];
            for (int share = 1; share <= totalShares; share++) {
                output[share - 1][offset] = (byte) evaluate(coefficients, share);
            }
        }
        java.util.ArrayList<ThresholdReKeyShare> shares = new java.util.ArrayList<>();
        for (int index = 1; index <= totalShares; index++) {
            shares.add(new ThresholdReKeyShare(threshold, totalShares, index, output[index - 1]));
        }
        return List.copyOf(shares);
    }

    public static byte[] combine(List<ThresholdReKeyShare> submitted) {
        if (submitted.isEmpty()) {
            throw new IllegalArgumentException("no threshold shares submitted");
        }
        ThresholdReKeyShare first = submitted.get(0);
        if (submitted.size() < first.threshold()) {
            throw new IllegalArgumentException("insufficient threshold shares");
        }
        Set<Integer> indexes = new HashSet<>();
        for (ThresholdReKeyShare share : submitted) {
            if (share.threshold() != first.threshold() || share.totalShares() != first.totalShares()
                    || share.value().length != first.value().length || !indexes.add(share.index())) {
                throw new IllegalArgumentException("incompatible threshold shares");
            }
        }
        byte[] secret = new byte[first.value().length];
        for (int offset = 0; offset < secret.length; offset++) {
            int value = 0;
            for (ThresholdReKeyShare left : submitted) {
                int coefficient = 1;
                for (ThresholdReKeyShare right : submitted) {
                    if (left.index() != right.index()) {
                        coefficient = multiply(coefficient, divide(right.index(), left.index() ^ right.index()));
                    }
                }
                value ^= multiply(left.value()[offset] & 0xff, coefficient);
            }
            secret[offset] = (byte) value;
        }
        return secret;
    }

    private static int evaluate(byte[] coefficients, int x) {
        int value = 0;
        for (int index = coefficients.length - 1; index >= 0; index--) {
            value = multiply(value, x) ^ (coefficients[index] & 0xff);
        }
        return value;
    }

    private static int divide(int numerator, int denominator) {
        if (denominator == 0) {
            throw new IllegalArgumentException("division by zero in threshold reconstruction");
        }
        return multiply(numerator, inverse(denominator));
    }

    private static int inverse(int value) {
        int result = 1;
        for (int index = 0; index < 254; index++) {
            result = multiply(result, value);
        }
        return result;
    }

    private static int multiply(int left, int right) {
        int result = 0;
        int a = left;
        int b = right;
        while (b != 0) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            a = (a << 1) ^ ((a & 0x80) != 0 ? 0x11b : 0);
            a &= 0xff;
            b >>>= 1;
        }
        return result;
    }
}
