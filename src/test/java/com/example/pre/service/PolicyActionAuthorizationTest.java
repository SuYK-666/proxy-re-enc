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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyActionAuthorizationTest {
    @Test
    void downloadDisabledPolicyStillAllowsProxyAndDemoDecryptAction() {
        Fixture f = new Fixture();
        AccessPolicy decryptOnly = new AccessPolicy(
                true,
                false,
                false,
                5,
                3,
                1,
                3,
                Instant.now().plus(1, ChronoUnit.DAYS),
                "preview/decrypt only",
                "decrypt"
        );
        var grant = f.createGrant(decryptOnly);
        var pkg = f.proxy.reEncrypt("proxy", grant.grantId());

        ReKeyShareException downloadDenied = assertThrows(ReKeyShareException.class,
                () -> f.objectAuth.assertCanDownloadPackage(f.bob.userId(), pkg.packageId()));
        assertEquals(ErrorCode.POLICY_VIOLATION, downloadDenied.code());

        assertDoesNotThrow(() -> f.objectAuth.assertCanDecryptPackage(f.bob.userId(), pkg.packageId()));
    }

    @Test
    void grantContextHashBindsPackageToGrantPolicyMetadata() {
        Fixture f = new Fixture();
        var grant = f.createGrant(AccessPolicy.normal(Instant.now().plus(1, ChronoUnit.DAYS)));
        var pkg = f.proxy.reEncrypt("proxy", grant.grantId());

        assertEquals(grant.policyHash(), pkg.grantPolicyHash());
        assertTrue(pkg.grantAad().length > 0);
        assertTrue(!pkg.grantContextHash().equals(pkg.ownerContextHash()));
    }

    @Test
    void tamperedGrantContextHashIsRejectedOnPackageAccess() {
        Fixture f = new Fixture();
        var grant = f.createGrant(AccessPolicy.normal(Instant.now().plus(1, ChronoUnit.DAYS)));
        var pkg = f.proxy.reEncrypt("proxy", grant.grantId());
        var tampered = new com.example.pre.model.ReEncryptedPackage(
                pkg.packageId(),
                pkg.grantId(),
                pkg.dataId(),
                pkg.ownerId(),
                pkg.recipientId(),
                pkg.algorithm(),
                pkg.encryptedContent(),
                pkg.contentNonce(),
                pkg.aad(),
                pkg.reEncryptedCapsule(),
                pkg.authorizedAt(),
                pkg.contentKeyVersion(),
                pkg.ciphertextStoragePath(),
                pkg.ownerKeyId(),
                pkg.policyHash(),
                pkg.grantPolicyHash(),
                pkg.ownerContextHash(),
                "tampered-context",
                pkg.grantAad(),
                pkg.status(),
                pkg.invalidatedAt(),
                pkg.invalidatedReason(),
                pkg.issuedManifestHash()
        );
        f.packageRepository.save(tampered);

        ReKeyShareException error = assertThrows(ReKeyShareException.class,
                () -> f.objectAuth.assertCanDownloadPackage(f.bob.userId(), pkg.packageId()));
        assertEquals(ErrorCode.AAD_MISMATCH, error.code());
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
        final com.example.pre.model.User alice = users.createUser("Alice");
        final com.example.pre.model.User bob = users.createUser("Bob");
        final com.example.pre.model.EncryptedDataPackage uploaded = data.upload(alice, Bytes.utf8("policy action"));

        com.example.pre.model.ShareGrant createGrant(AccessPolicy policy) {
            var context = com.example.pre.crypto.ecc.ReKeySessionContext.create();
            var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, context);
            return authorization.createGrantWithRecipientShare(alice, bob, uploaded, policy, share, context);
        }
    }
}
