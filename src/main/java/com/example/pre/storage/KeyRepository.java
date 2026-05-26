package com.example.pre.storage;

import com.example.pre.model.KeyVersion;

import java.util.Collection;
import java.util.Optional;

public interface KeyRepository {
    void save(KeyVersion keyVersion);

    Optional<KeyVersion> findById(String keyId);

    Collection<KeyVersion> findByUserId(String userId);
}
