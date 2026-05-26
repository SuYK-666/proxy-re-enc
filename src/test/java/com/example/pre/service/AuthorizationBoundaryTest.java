package com.example.pre.service;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.ecc.ReKeySessionContext;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.User;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthorizationBoundaryTest {
    @Test
    void eccRecipientShareGrantRequiresDataOwner() {
        EccPreScheme scheme = new EccPreScheme();
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        DataSecurityService data = new DataSecurityService(scheme, dataRepository, audit);
        AuthorizationService authorization = new AuthorizationService(scheme, audit, new InMemoryGrantRepository());
        User alice = users.createUser("Alice");
        User bob = users.createUser("Bob");
        User charlie = users.createUser("Charlie");
        var uploaded = data.upload(alice, Bytes.utf8("owner-only"));
        ReKeySessionContext context = ReKeySessionContext.create();
        var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, context);

        ReKeyShareException error = assertThrows(ReKeyShareException.class,
                () -> authorization.createGrantWithRecipientShare(
                        charlie, bob, uploaded, AccessPolicy.normal(Instant.now().plus(1, ChronoUnit.DAYS)), share, context));
        assertEquals(ErrorCode.ACCESS_DENIED, error.code());
    }

    @Test
    void eccRecipientShareGrantRejectsAlgorithmMismatch() {
        RsaPreScheme rsa = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        EccPreScheme ecc = new EccPreScheme();
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        UserService rsaUsers = new UserService(rsa, new InMemoryUserRepository(), audit);
        DataSecurityService rsaData = new DataSecurityService(rsa, new InMemoryDataRepository(), audit);
        AuthorizationService eccAuthorization = new AuthorizationService(ecc, audit, new InMemoryGrantRepository());
        User alice = rsaUsers.createUser("Alice");
        User bob = new User("Bob", ecc.generateKeyPair("Bob"));
        var uploaded = rsaData.upload(alice, Bytes.utf8("rsa-data"));
        ReKeySessionContext context = ReKeySessionContext.create();
        var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, context);

        ReKeyShareException error = assertThrows(ReKeyShareException.class,
                () -> eccAuthorization.createGrantWithRecipientShare(
                        alice, bob, uploaded, AccessPolicy.normal(Instant.now().plus(1, ChronoUnit.DAYS)), share, context));
        assertEquals(ErrorCode.ALGORITHM_MISMATCH, error.code());
        assertEquals(AlgorithmType.RSA_PRE, uploaded.algorithm());
    }
}
