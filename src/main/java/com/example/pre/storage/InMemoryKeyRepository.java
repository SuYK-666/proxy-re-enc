package com.example.pre.storage;

import com.example.pre.model.KeyVersion;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public final class InMemoryKeyRepository implements KeyRepository {
    private final Map<String, KeyVersion> keys = new LinkedHashMap<>();

    @Override
    public synchronized void save(KeyVersion keyVersion) {
        keys.put(keyVersion.keyId(), keyVersion);
    }

    @Override
    public synchronized Optional<KeyVersion> findById(String keyId) {
        return Optional.ofNullable(keys.get(keyId));
    }

    @Override
    public synchronized Collection<KeyVersion> findByUserId(String userId) {
        return keys.values().stream().filter(key -> key.userId().equals(userId)).toList();
    }
}
