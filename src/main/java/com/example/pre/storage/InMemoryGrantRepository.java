package com.example.pre.storage;

import com.example.pre.model.ShareGrant;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class InMemoryGrantRepository implements GrantRepository {
    private final Map<String, ShareGrant> grants = new LinkedHashMap<>();

    @Override
    public synchronized void save(ShareGrant grant) {
        grants.put(grant.grantId(), grant);
    }

    @Override
    public synchronized Optional<ShareGrant> findById(String grantId) {
        return Optional.ofNullable(grants.get(grantId));
    }

    @Override
    public synchronized Collection<ShareGrant> findAll() {
        return List.copyOf(grants.values());
    }

    @Override
    public synchronized Collection<ShareGrant> findByDataId(String dataId) {
        return grants.values().stream().filter(grant -> grant.dataId().equals(dataId)).toList();
    }
}
