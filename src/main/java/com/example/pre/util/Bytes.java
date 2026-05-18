package com.example.pre.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class Bytes {
    private Bytes() {
    }

    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    public static byte[] unsignedFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        if (raw.length == length + 1 && raw[0] == 0) {
            return Arrays.copyOfRange(raw, 1, raw.length);
        }
        if (raw.length > length) {
            throw new IllegalArgumentException("integer does not fit in fixed length");
        }
        byte[] out = new byte[length];
        System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        return out;
    }

    public static BigInteger positiveBigInteger(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    public static String hex(byte[] bytes, int maxBytes) {
        int len = Math.min(bytes.length, maxBytes);
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > maxBytes) {
            sb.append("...");
        }
        return sb.toString();
    }
}
