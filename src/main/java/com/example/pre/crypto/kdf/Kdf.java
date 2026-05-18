package com.example.pre.crypto.kdf;

import com.example.pre.util.Bytes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class Kdf {
    private Kdf() {
    }

    public static byte[] sha256(String label, byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(Bytes.utf8(label));
            digest.update((byte) 0);
            digest.update(input);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
