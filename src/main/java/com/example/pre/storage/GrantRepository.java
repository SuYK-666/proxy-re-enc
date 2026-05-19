package com.example.pre.storage;

import com.example.pre.model.ShareGrant;

import java.util.Collection;
import java.util.Optional;

public interface GrantRepository {
    void save(ShareGrant grant);

    Optional<ShareGrant> findById(String grantId);

    Collection<ShareGrant> findAll();

    Collection<ShareGrant> findByDataId(String dataId);
}
