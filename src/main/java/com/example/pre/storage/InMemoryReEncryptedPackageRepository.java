package com.example.pre.storage;

import com.example.pre.model.ReEncryptedPackage;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class InMemoryReEncryptedPackageRepository implements ReEncryptedPackageRepository {
    private final Map<String, ReEncryptedPackage> packages = new LinkedHashMap<>();

    @Override
    public synchronized void save(ReEncryptedPackage dataPackage) {
        packages.put(dataPackage.packageId(), dataPackage);
    }

    @Override
    public synchronized Optional<ReEncryptedPackage> findById(String packageId) {
        return Optional.ofNullable(packages.get(packageId));
    }

    @Override
    public synchronized Collection<ReEncryptedPackage> findAll() {
        return List.copyOf(packages.values());
    }
}
