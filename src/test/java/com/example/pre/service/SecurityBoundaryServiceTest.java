package com.example.pre.service;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.model.AccessPolicy;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNull;

class SecurityBoundaryServiceTest {
    @Test
    void encryptedPackageModelDoesNotExposePlaintextOrDemoHashFields() {
        EccPreScheme scheme = new EccPreScheme();
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        DataSecurityService data = new DataSecurityService(scheme, new InMemoryDataRepository(), audit);

        var alice = users.createUser("Alice");
        var uploaded = data.upload(alice, Bytes.utf8("plaintext should stay transient"));

        assertFalse(java.util.Arrays.stream(uploaded.getClass().getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName)
                .anyMatch(name -> name.toLowerCase().contains("plaintexthash")
                        || name.toLowerCase().contains("plaintextbytes")
                        || "plaintext".equalsIgnoreCase(name)));
    }

    @Test
    void legacyAuthorizePathIsDisabled() {
        EccPreScheme scheme = new EccPreScheme();
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        DataSecurityService data = new DataSecurityService(scheme, new InMemoryDataRepository(), audit);
        AuthorizationService authorization = new AuthorizationService(scheme, audit, new InMemoryGrantRepository());

        var alice = users.createUser("Alice");
        var bob = users.createUser("Bob");
        var uploaded = data.upload(alice, Bytes.utf8("legacy path"));

        assertThrows(UnsupportedOperationException.class, () -> authorization.authorize(alice, bob, uploaded));
    }

    @Test
    void eccGrantWithoutRecipientShareFails() {
        EccPreScheme scheme = new EccPreScheme();
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        DataSecurityService data = new DataSecurityService(scheme, new InMemoryDataRepository(), audit);
        AuthorizationService authorization = new AuthorizationService(scheme, audit, new InMemoryGrantRepository());

        var alice = users.createUser("Alice");
        var bob = users.createUser("Bob");
        var uploaded = data.upload(alice, Bytes.utf8("recipient share required"));

        assertThrows(ReKeyShareException.class, () -> authorization.createGrant(
                alice,
                bob,
                uploaded,
                AccessPolicy.normal(Instant.now().plus(1, ChronoUnit.DAYS))
        ));
    }

    @Test
    void productionStylePublicRegistrationDoesNotPersistPrivateKey() {
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        InMemoryUserRepository repository = new InMemoryUserRepository();
        UserService users = new UserService(new EccPreScheme(), repository, audit);
        users.registerPublicOnlyUser("Alice", com.example.pre.model.UserRole.OWNER);

        assertNull(repository.findById("Alice").orElseThrow().keyPair().privateKey());
    }
}
