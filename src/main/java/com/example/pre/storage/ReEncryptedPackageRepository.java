package com.example.pre.storage;

import com.example.pre.model.ReEncryptedPackage;

import java.util.Collection;
import java.util.Optional;

public interface ReEncryptedPackageRepository {
    void save(ReEncryptedPackage dataPackage);

    Optional<ReEncryptedPackage> findById(String packageId);

    Collection<ReEncryptedPackage> findAll();
}
