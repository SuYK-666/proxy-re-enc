package com.example.pre.service;

import com.example.pre.crypto.PreScheme;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.User;
import com.example.pre.model.UserRole;
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
        return createUser(userId, UserRole.RECIPIENT);
    }

    public User createUser(String userId, UserRole role) {
        User user = new User(userId, scheme.generateKeyPair(userId)).withRole(role);
        users.save(user);
        audit.record(new AuditEvent(Instant.now(), userId, "KEYGEN", userId, true, scheme.name()));
        return user;
    }

    public User registerPublicOnlyUser(String userId, UserRole role) {
        com.example.pre.model.UserKeyPair transientPair = scheme.generateKeyPair(userId);
        User user = new User(userId, new com.example.pre.model.UserKeyPair(
                userId, transientPair.publicKey(), null)).withRole(role);
        users.save(user);
        audit.record(new AuditEvent(Instant.now(), userId, "PUBLIC_KEY_REGISTER", userId, true, scheme.name()));
        return user;
    }

    public User rotateUserKey(User current) {
        User rotated = new User(current.userId(), scheme.generateKeyPair(current.userId()),
                current.username(), current.role(), current.status(), current.createdAt());
        users.save(rotated);
        audit.record(new AuditEvent(Instant.now(), current.userId(), "USER_KEYPAIR_ROTATE", current.userId(), true, scheme.name()));
        return rotated;
    }
}
