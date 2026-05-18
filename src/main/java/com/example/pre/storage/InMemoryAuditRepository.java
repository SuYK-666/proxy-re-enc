package com.example.pre.storage;

import com.example.pre.model.AuditEvent;

import java.util.ArrayList;
import java.util.List;

public final class InMemoryAuditRepository implements AuditRepository {
    private final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void record(AuditEvent event) {
        events.add(event);
    }

    @Override
    public List<AuditEvent> findAll() {
        return List.copyOf(events);
    }
}
