package com.example.pre.crypto.hash;

import com.example.pre.util.Bytes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Hash {
    private Hash() {
    }

    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static String sha256Hex(String input) {
        return Bytes.hex(sha256(Bytes.utf8(input)), 32);
    }

    public static String sha256Hex(byte[] input) {
        return Bytes.hex(sha256(input), 32);
    }
}
