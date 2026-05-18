package com.example.pre.storage;

import com.example.pre.model.EncryptedDataPackage;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public final class InMemoryDataRepository implements DataRepository {
    private final Map<String, EncryptedDataPackage> data = new LinkedHashMap<>();

    @Override
    public void save(EncryptedDataPackage dataPackage) {
        data.put(dataPackage.dataId(), dataPackage);
    }

    @Override
    public Optional<EncryptedDataPackage> findById(String dataId) {
        return Optional.ofNullable(data.get(dataId));
    }

    @Override
    public Collection<EncryptedDataPackage> findAll() {
        return data.values();
    }
}
