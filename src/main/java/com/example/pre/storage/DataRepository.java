package com.example.pre.storage;

import com.example.pre.model.EncryptedDataPackage;

import java.util.Collection;
import java.util.Optional;

public interface DataRepository {
    void save(EncryptedDataPackage dataPackage);

    Optional<EncryptedDataPackage> findById(String dataId);

    Collection<EncryptedDataPackage> findAll();
}
