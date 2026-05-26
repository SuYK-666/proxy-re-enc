package com.example.pre.storage;

import com.example.pre.model.User;

import java.util.Collection;
import java.util.Optional;

public interface UserRepository {
    void save(User user);

    Optional<User> findById(String userId);

    Collection<User> findAll();
}
