package com.example.pre.crypto.symmetric;

import com.example.pre.crypto.hash.Hash;

import java.io.IOException;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class AesGcmNonceManager {
    private static final Set<String> USED_NONCES = ConcurrentHashMap.newKeySet();
    private static final Path REGISTRY = Path.of(System.getProperty(
            "rekeyshare.nonce.registry",
            "storage/security/aes-gcm-nonces.txt"
    ));
    private static boolean loaded;

    private AesGcmNonceManager() {
    }

    public static synchronized boolean reserve(byte[] key, byte[] nonce) {
        if (nonce.length != AesGcm.NONCE_BYTES) {
            throw new IllegalArgumentException("AES-GCM nonce must be 12 bytes");
        }
        String keyFingerprint = Hash.sha256Hex(key);
        String nonceValue = Base64.getEncoder().encodeToString(nonce);
        String entry = keyFingerprint + ":" + nonceValue;
        ensureRegistryLoaded();
        if (!USED_NONCES.add(entry)) {
            return false;
        }
        persist(entry);
        return true;
    }

    static synchronized void clearForTest() {
        USED_NONCES.clear();
        loaded = true;
        try {
            Files.deleteIfExists(REGISTRY);
        } catch (IOException e) {
            throw new IllegalStateException("failed to clear nonce registry", e);
        }
    }

    static synchronized void clearMemoryForRestartTest() {
        USED_NONCES.clear();
        loaded = false;
    }

    private static void ensureRegistryLoaded() {
        if (loaded) {
            return;
        }
        if (!Files.exists(REGISTRY)) {
            loaded = true;
            return;
        }
        try {
            USED_NONCES.addAll(Files.readAllLines(REGISTRY));
            loaded = true;
        } catch (IOException e) {
            throw new IllegalStateException("failed to read AES-GCM nonce registry", e);
        }
    }

    private static void persist(String entry) {
        try {
            if (REGISTRY.getParent() != null) {
                Files.createDirectories(REGISTRY.getParent());
            }
            Files.writeString(REGISTRY, entry + System.lineSeparator(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            USED_NONCES.remove(entry);
            throw new IllegalStateException("failed to persist AES-GCM nonce reservation", e);
        }
    }
}
