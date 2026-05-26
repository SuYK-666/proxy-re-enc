package com.example.pre.service;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryReEncryptedPackageRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.AadBuilder;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyLifecycleServiceTest {
    @Test
    void hardRevokeInvalidatesOldPackageAndAdvancesOwnerPreparedKeyVersion() {
        Fixture f = new Fixture();
        var grant = f.grantFor(f.bob);
        var oldPackage = f.proxy.reEncrypt("proxy", grant.grantId());
        var result = f.lifecycle.hardRevoke(f.alice, grant.grantId(), "recipient offboarded",
                f.rotatedPackage());

        assertEquals(KeyLifecycleService.RevocationMode.HARD_REVOKE, result.mode());
        assertEquals(2, result.newContentKeyVersion());
        ErrorCode blocked = assertThrows(ReKeyShareException.class,
                () -> f.objectAuth.assertCanDownloadPackage(f.bob.userId(), oldPackage.packageId())).code();
        assertTrue(blocked == ErrorCode.GRANT_REVOKED || blocked == ErrorCode.GRANT_ROTATED);
    }

    @Test
    void emergencyRevokeBlocksEveryActiveGrantBeforeRotation() {
        Fixture f = new Fixture();
        var bob = f.grantFor(f.bob);
        var carol = f.grantFor(f.carol);
        var result = f.lifecycle.emergencyRevoke(f.alice, f.uploaded.dataId(), "key compromise", f.rotatedPackage());

        assertEquals(2, result.revokedGrants());
        assertEquals(com.example.pre.model.GrantStatus.REVOKED, f.grants.findById(bob.grantId()).orElseThrow().status());
        assertEquals(com.example.pre.model.GrantStatus.REVOKED, f.grants.findById(carol.grantId()).orElseThrow().status());
    }

    private static final class Fixture {
        final EccPreScheme scheme = new EccPreScheme();
        final InMemoryAuditRepository audit = new InMemoryAuditRepository();
        final InMemoryDataRepository dataRepo = new InMemoryDataRepository();
        final InMemoryGrantRepository grants = new InMemoryGrantRepository();
        final InMemoryReEncryptedPackageRepository packages = new InMemoryReEncryptedPackageRepository();
        final UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        final DataSecurityService data = new DataSecurityService(scheme, dataRepo, audit);
        final AuthorizationService authorization = new AuthorizationService(scheme, audit, grants);
        final ObjectAuthorizationService objectAuth = new ObjectAuthorizationService(dataRepo, grants, packages, audit);
        final ProxyReEncryptionService proxy = new ProxyReEncryptionService(scheme, dataRepo, grants, packages, objectAuth, audit);
        final RevocationService revocation = new RevocationService(scheme, dataRepo, grants, packages, objectAuth, audit);
        final KeyLifecycleService lifecycle = new KeyLifecycleService(revocation, grants, audit);
        final com.example.pre.model.User alice = users.createUser("Alice");
        final com.example.pre.model.User bob = users.createUser("Bob");
        final com.example.pre.model.User carol = users.createUser("Carol");
        final EncryptedDataPackage uploaded = data.upload(alice, Bytes.utf8("lifecycle"));

        com.example.pre.model.ShareGrant grantFor(com.example.pre.model.User recipient) {
            var context = com.example.pre.crypto.ecc.ReKeySessionContext.create();
            return authorization.createGrantWithRecipientShare(alice, recipient, uploaded,
                    AccessPolicy.normal(Instant.now().plusSeconds(600)),
                    DemoPrivateKeyStore.createEccRecipientShareLocally(recipient, context), context);
        }

        EncryptedDataPackage rotatedPackage() {
            int version = uploaded.contentKeyVersion() + 1;
            CapsuleContext context = new CapsuleContext(uploaded.dataId(), alice.userId(), alice.userId(),
                    uploaded.algorithm(), uploaded.ownerKeyId(), version, "ROTATED");
            byte[] dek = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
            try {
                byte[] aad = AadBuilder.build(context);
                AesGcm.CipherText encrypted = AesGcm.encrypt(dek, Bytes.utf8("lifecycle"), aad);
                return uploaded.withOwnerSideEncryptedVersion(encrypted.ciphertext(), encrypted.nonce(), aad,
                        scheme.encapsulate(dek, alice.keyPair().publicKey(), context), version, "ROTATED",
                        com.example.pre.crypto.hash.Hash.sha256Hex(aad));
            } finally {
                Arrays.fill(dek, (byte) 0);
            }
        }
    }
}
