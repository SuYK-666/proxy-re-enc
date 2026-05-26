package com.example.pre.benchmark;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Deterministic plaintext fixtures for performance experiments only.
 * This generator must never be used for cryptographic key or nonce material.
 */
public final class ReproducibleDataset {
    private static final long SEED = 0x52454b5348415245L;
    private static final List<String> DISTRIBUTIONS = List.of(
            "deterministic-random", "zero-heavy", "text-json", "binary-image-like", "compressible");

    private ReproducibleDataset() {
    }

    public static List<String> distributions() {
        return DISTRIBUTIONS;
    }

    public static byte[] generate(String distribution, int size, int round) {
        byte[] bytes = new byte[size];
        long seed = SEED ^ ((long) size << 16) ^ round;
        switch (distribution) {
            case "deterministic-random" -> fillRandom(bytes, seed);
            case "zero-heavy" -> {
                byte[] source = new byte[size];
                fillRandom(source, seed);
                for (int index = 0; index < size; index += 16) {
                    bytes[index] = source[index];
                }
            }
            case "text-json" -> repeat(bytes,
                    ("{\"tenant\":\"tenant-a\",\"event\":\"share\",\"round\":" + round + "}\n")
                            .getBytes(StandardCharsets.US_ASCII));
            case "binary-image-like" -> {
                for (int index = 0; index < size; index++) {
                    int pixel = index % 1024;
                    bytes[index] = (byte) ((pixel / 4 + round) & 0xff);
                }
            }
            case "compressible" -> repeat(bytes, "ReKeyShare|payload|v1|".getBytes(StandardCharsets.US_ASCII));
            default -> throw new IllegalArgumentException("unknown dataset distribution: " + distribution);
        }
        return bytes;
    }

    private static void fillRandom(byte[] bytes, long seed) {
        long state = seed;
        for (int index = 0; index < bytes.length; index++) {
            state ^= state << 13;
            state ^= state >>> 7;
            state ^= state << 17;
            bytes[index] = (byte) state;
        }
    }

    private static void repeat(byte[] bytes, byte[] pattern) {
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = pattern[index % pattern.length];
        }
    }
}
