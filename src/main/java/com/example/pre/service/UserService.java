package com.example.pre.service;

import com.example.pre.crypto.PreScheme;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.User;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.UserRepository;

import java.time.Instant;

public final class UserService {
    private final PreScheme scheme;
    private final UserRepository users;
    private final AuditRepository audit;

    public UserService(PreScheme scheme, UserRepository users, AuditRepository audit) {
        this.scheme = scheme;
        this.users = users;
        this.audit = audit;
    }

    public User createUser(String userId) {
        User user = new User(userId, scheme.generateKeyPair(userId));
        users.save(user);
        audit.record(new AuditEvent(Instant.now(), userId, "KEYGEN", userId, true, scheme.name()));
        return user;
    }
}
