package com.example.pre.service;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.model.AccessPolicy;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryReEncryptedPackageRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GrantAccessCountTest {
    @Test
    void proxyReEncryptDoesNotConsumeRecipientAccessCount() {
        Fixture f = new Fixture();
        AccessPolicy policy = new AccessPolicy(
                true,
                true,
                false,
                1,
                3,
                1,
                1,
                Instant.now().plus(1, ChronoUnit.DAYS),
                "single recipient download",
                "download,decrypt"
        );
        var grant = f.createGrant(policy);

        var pkg = f.proxy.reEncrypt("proxy", grant.grantId());
        var afterProxy = f.grants.findById(grant.grantId()).orElseThrow();
        assertEquals(0, afterProxy.accessCount());
        assertEquals(1, afterProxy.reEncryptCount());

        f.objectAuth.assertCanDownloadPackage(f.bob.userId(), pkg.packageId());
        f.grants.save(afterProxy.incrementDownload());
        assertThrows(ReKeyShareException.class,
                () -> f.objectAuth.assertCanDownloadPackage(f.bob.userId(), pkg.packageId()));
    }

    private static final class Fixture {
        final EccPreScheme scheme = new EccPreScheme();
        final InMemoryAuditRepository audit = new InMemoryAuditRepository();
        final InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        final InMemoryGrantRepository grants = new InMemoryGrantRepository();
        final InMemoryReEncryptedPackageRepository packages = new InMemoryReEncryptedPackageRepository();
        final UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        final DataSecurityService data = new DataSecurityService(scheme, dataRepository, audit);
        final AuthorizationService authorization = new AuthorizationService(scheme, audit, grants);
        final ObjectAuthorizationService objectAuth = new ObjectAuthorizationService(dataRepository, grants, packages, audit);
        final ProxyReEncryptionService proxy = new ProxyReEncryptionService(scheme, dataRepository, grants, packages, objectAuth, audit);
        final com.example.pre.model.User alice = users.createUser("Alice");
        final com.example.pre.model.User bob = users.createUser("Bob");
        final com.example.pre.model.EncryptedDataPackage uploaded = data.upload(alice, Bytes.utf8("count semantics"));

        com.example.pre.model.ShareGrant createGrant(AccessPolicy policy) {
            var context = com.example.pre.crypto.ecc.ReKeySessionContext.create();
            var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, context);
            return authorization.createGrantWithRecipientShare(alice, bob, uploaded, policy, share, context);
        }
    }
}
