package com.example.pre.service;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.GrantStatus;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.service.DemoPrivateKeyStore;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryReEncryptedPackageRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;
import com.example.pre.util.PolicyDigest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationPolicyTest {
    @Test
    void ownerCanCreatePolicyBoundGrant() {
        Fixture f = new Fixture();
        ShareGrant grant = f.createGrant(AccessPolicy.normal(Instant.now().plus(1, ChronoUnit.DAYS)));
        assertEquals(GrantStatus.ACTIVE, grant.status());
        assertEquals(PolicyDigest.sha256(grant.policy()), grant.policyHash());
    }

    @Test
    void wrongOwnerCannotCreateGrantForAliceData() {
        Fixture f = new Fixture();
        assertThrows(ReKeyShareException.class,
                () -> f.objectAuth.assertCanCreateGrant(f.bob.userId(), f.uploaded.dataId()));
    }

    @Test
    void expiredGrantIsRejectedByProxy() {
        Fixture f = new Fixture();
        ShareGrant expired = f.createGrant(new AccessPolicy(true, true, false, 10,
                Instant.now().minus(1, ChronoUnit.HOURS), "expired"));
        ReKeyShareException error = assertThrows(ReKeyShareException.class,
                () -> f.proxy.reEncrypt("proxy", expired.grantId()));
        assertEquals(ErrorCode.GRANT_EXPIRED, error.code());
    }

    @Test
    void maxAccessCountIsEnforced() {
        Fixture f = new Fixture();
        ShareGrant grant = f.createGrant(new AccessPolicy(true, true, false, 1,
                Instant.now().plus(1, ChronoUnit.DAYS), "once"));
        f.proxy.reEncrypt("proxy", grant.grantId());
        ReKeyShareException error = assertThrows(ReKeyShareException.class,
                () -> f.proxy.reEncrypt("proxy", grant.grantId()));
        assertEquals(ErrorCode.POLICY_VIOLATION, error.code());
    }

    @Test
    void revokedGrantIsRejected() {
        Fixture f = new Fixture();
        ShareGrant grant = f.createGrant(AccessPolicy.normal(Instant.now().plus(1, ChronoUnit.DAYS)));
        f.revocation.revokeGrant(f.alice.userId(), grant.grantId());
        ReKeyShareException error = assertThrows(ReKeyShareException.class,
                () -> f.proxy.reEncrypt("proxy", grant.grantId()));
        assertEquals(ErrorCode.GRANT_REVOKED, error.code());
    }

    @Test
    void policyHashChangesWhenPolicyIsTampered() {
        AccessPolicy original = new AccessPolicy(true, true, false, 5,
                Instant.now().plus(1, ChronoUnit.DAYS), "normal");
        AccessPolicy tampered = new AccessPolicy(true, true, false, 6,
                original.expiresAt(), "normal");
        assertNotEquals(PolicyDigest.sha256(original), PolicyDigest.sha256(tampered));
        assertTrue(original.canonicalJson().contains("\"maxAccessCount\":5"));
    }

    private static final class Fixture {
        final EccPreScheme scheme = new EccPreScheme();
        final InMemoryAuditRepository audit = new InMemoryAuditRepository();
        final InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        final InMemoryGrantRepository grantRepository = new InMemoryGrantRepository();
        final InMemoryReEncryptedPackageRepository packageRepository = new InMemoryReEncryptedPackageRepository();
        final UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        final DataSecurityService data = new DataSecurityService(scheme, dataRepository, audit);
        final AuthorizationService authorization = new AuthorizationService(scheme, audit, grantRepository);
        final ObjectAuthorizationService objectAuth = new ObjectAuthorizationService(dataRepository, grantRepository, packageRepository, audit);
        final ProxyReEncryptionService proxy = new ProxyReEncryptionService(scheme, dataRepository, grantRepository, packageRepository, objectAuth, audit);
        final RevocationService revocation = new RevocationService(scheme, dataRepository, grantRepository, objectAuth, audit);
        final User alice = users.createUser("Alice");
        final User bob = users.createUser("Bob");
        final com.example.pre.model.EncryptedDataPackage uploaded = data.upload(alice, Bytes.utf8("private"));

        ShareGrant createGrant(AccessPolicy policy) {
            var context = com.example.pre.crypto.ecc.ReKeySessionContext.create();
            var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, context);
            return authorization.createGrantWithRecipientShare(alice, bob, uploaded, policy, share, context);
        }
    }
}
