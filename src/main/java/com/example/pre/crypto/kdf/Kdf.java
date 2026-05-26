package com.example.pre.crypto.kdf;

import com.example.pre.util.Bytes;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Kdf {
    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LEN = 32;

    private Kdf() {
    }

    /**
     * Backward-compatible entry point now implemented as HKDF-SHA256.
     * The label is used as protocol info for domain separation.
     */
    public static byte[] sha256(String label, byte[] input) {
        return hkdfSha256(null, input, Bytes.utf8(label), HASH_LEN);
    }

    public static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int length) {
        if (length < 1 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("invalid HKDF output length");
        }
        byte[] prk = extract(salt, ikm);
        return expand(prk, info == null ? new byte[0] : info, length);
    }

    public static byte[] extract(byte[] salt, byte[] ikm) {
        byte[] actualSalt = salt == null || salt.length == 0 ? new byte[HASH_LEN] : salt.clone();
        return hmac(actualSalt, ikm == null ? new byte[0] : ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) {
        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        int counter = 1;
        while (offset < length) {
            byte[] input = new byte[previous.length + info.length + 1];
            System.arraycopy(previous, 0, input, 0, previous.length);
            System.arraycopy(info, 0, input, previous.length, info.length);
            input[input.length - 1] = (byte) counter++;
            previous = hmac(prk, input);
            int toCopy = Math.min(previous.length, length - offset);
            System.arraycopy(previous, 0, out, offset, toCopy);
            offset += toCopy;
            Arrays.fill(input, (byte) 0);
        }
        Arrays.fill(previous, (byte) 0);
        return out;
    }

    private static byte[] hmac(byte[] key, byte[] input) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        } catch (Exception e) {
            throw new IllegalStateException("HKDF failed", e);
        }
    }
}
