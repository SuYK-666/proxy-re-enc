package com.example.pre.scenario;

import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.GrantStatus;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.service.AuditService;
import com.example.pre.service.AuthorizationService;
import com.example.pre.service.DataSecurityService;
import com.example.pre.service.DemoPrivateKeyStore;
import com.example.pre.service.ErrorCode;
import com.example.pre.service.ObjectAuthorizationService;
import com.example.pre.service.ProxyReEncryptionService;
import com.example.pre.service.ReKeyShareException;
import com.example.pre.service.RevocationService;
import com.example.pre.service.UserService;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryReEncryptedPackageRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.AadBuilder;
import com.example.pre.util.Bytes;
import com.example.pre.util.PolicyDigest;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReKeyShareLifecycleTest {
    @Test
    void rsaLifecycleCoversGrantProxyRevokeRotateAndAudit() {
        runLifecycle(new RsaPreScheme(RsaCommonModulusParameters.generate(1024)));
    }

    @Test
    void eccLifecycleCoversGrantProxyRevokeRotateAndAudit() {
        runLifecycle(new EccPreScheme());
    }

    private static void runLifecycle(PreScheme scheme) {
        InMemoryAuditRepository auditRepository = new InMemoryAuditRepository();
        InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        InMemoryGrantRepository grantRepository = new InMemoryGrantRepository();
        InMemoryReEncryptedPackageRepository packageRepository = new InMemoryReEncryptedPackageRepository();

        UserService users = new UserService(scheme, new InMemoryUserRepository(), auditRepository);
        DataSecurityService dataService = new DataSecurityService(scheme, dataRepository, auditRepository);
        AuthorizationService authorization = new AuthorizationService(scheme, auditRepository, grantRepository);
        ObjectAuthorizationService objectAuth = new ObjectAuthorizationService(
                dataRepository, grantRepository, packageRepository, auditRepository);
        ProxyReEncryptionService proxy = new ProxyReEncryptionService(
                scheme, dataRepository, grantRepository, packageRepository, objectAuth, auditRepository);
        RevocationService revocation = new RevocationService(
                scheme, dataRepository, grantRepository, objectAuth, auditRepository);
        AuditService audit = new AuditService(auditRepository);

        User alice = users.createUser("Alice");
        User bob = users.createUser("Bob");
        User charlie = users.createUser("Charlie");
        byte[] plaintext = Bytes.utf8("policy-bound PRE lifecycle document");

        var uploaded = dataService.upload(new DataSecurityService.UploadDataCommand(
                alice, plaintext, "course-report.txt", "text/plain"));
        AccessPolicy normal = AccessPolicy.normal(Instant.now().plus(7, ChronoUnit.DAYS));
        assertEquals(PolicyDigest.sha256(normal), PolicyDigest.sha256(normal));

        ShareGrant grant = createGrant(authorization, scheme, alice, bob, uploaded, normal);
        assertEquals(GrantStatus.ACTIVE, grant.status());

        ReEncryptedPackage bobPackage = proxy.reEncrypt("proxy", grant.grantId());
        objectAuth.assertCanDownloadPackage(bob.userId(), bobPackage.packageId());
        assertArrayEquals(plaintext, dataService.decryptReEncrypted(bob, bobPackage));

        ReKeyShareException denied = assertThrows(
                ReKeyShareException.class,
                () -> objectAuth.assertCanDownloadPackage(charlie.userId(), bobPackage.packageId())
        );
        assertEquals(ErrorCode.ACCESS_DENIED, denied.code());

        ShareGrant revoked = revocation.revokeGrant(alice.userId(), grant.grantId());
        assertEquals(GrantStatus.REVOKED, revoked.status());
        ReKeyShareException revokedFailure = assertThrows(
                ReKeyShareException.class,
                () -> objectAuth.assertCanDownloadPackage(bob.userId(), bobPackage.packageId())
        );
        assertEquals(ErrorCode.GRANT_REVOKED, revokedFailure.code());

        var rotated = revocation.acceptOwnerSideRotation(alice, prepareOwnerSideRotation(scheme, alice, uploaded, plaintext));
        assertEquals(uploaded.contentKeyVersion() + 1, rotated.contentKeyVersion());

        assertTrue(audit.verifyChain().valid());
        auditRepository.replaceForDemo(1, auditRepository.findAll().get(1).withAction("TAMPERED_ACTION"));
        assertFalse(audit.verifyChain().valid());
    }

    @Test
    void expiredAndLimitedGrantsAreRejected() {
        PreScheme scheme = new EccPreScheme();
        InMemoryAuditRepository auditRepository = new InMemoryAuditRepository();
        InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        InMemoryGrantRepository grantRepository = new InMemoryGrantRepository();
        InMemoryReEncryptedPackageRepository packageRepository = new InMemoryReEncryptedPackageRepository();
        UserService users = new UserService(scheme, new InMemoryUserRepository(), auditRepository);
        DataSecurityService dataService = new DataSecurityService(scheme, dataRepository, auditRepository);
        AuthorizationService authorization = new AuthorizationService(scheme, auditRepository, grantRepository);
        ObjectAuthorizationService objectAuth = new ObjectAuthorizationService(
                dataRepository, grantRepository, packageRepository, auditRepository);
        ProxyReEncryptionService proxy = new ProxyReEncryptionService(
                scheme, dataRepository, grantRepository, packageRepository, objectAuth, auditRepository);

        User alice = users.createUser("Alice");
        User bob = users.createUser("Bob");
        var uploaded = dataService.upload(alice, Bytes.utf8("private"));

        AccessPolicy expiredPolicy = new AccessPolicy(true, true, false, 10,
                Instant.now().minus(1, ChronoUnit.HOURS), "expired");
        ShareGrant expired = createGrant(authorization, scheme, alice, bob, uploaded, expiredPolicy);
        ReKeyShareException expiredFailure = assertThrows(
                ReKeyShareException.class,
                () -> proxy.reEncrypt("proxy", expired.grantId())
        );
        assertEquals(ErrorCode.GRANT_EXPIRED, expiredFailure.code());

        AccessPolicy once = new AccessPolicy(true, true, false, 1,
                Instant.now().plus(7, ChronoUnit.DAYS), "single-use");
        ShareGrant limited = createGrant(authorization, scheme, alice, bob, uploaded, once);
        proxy.reEncrypt("proxy", limited.grantId());
        ReKeyShareException secondUse = assertThrows(
                ReKeyShareException.class,
                () -> proxy.reEncrypt("proxy", limited.grantId())
        );
        assertEquals(ErrorCode.POLICY_VIOLATION, secondUse.code());
    }

    private static ShareGrant createGrant(
            AuthorizationService authorization,
            PreScheme scheme,
            User alice,
            User bob,
            com.example.pre.model.EncryptedDataPackage uploaded,
            AccessPolicy policy
    ) {
        if (scheme instanceof EccPreScheme) {
            var context = com.example.pre.crypto.ecc.ReKeySessionContext.create();
            var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, context);
            return authorization.createGrantWithRecipientShare(alice, bob, uploaded, policy, share, context);
        }
        return authorization.createGrant(alice, bob, uploaded, policy);
    }

    private static EncryptedDataPackage prepareOwnerSideRotation(
            PreScheme scheme,
            User owner,
            EncryptedDataPackage current,
            byte[] localPlaintext
    ) {
        int newVersion = current.contentKeyVersion() + 1;
        String policyHash = "ROTATED_V" + newVersion;
        CapsuleContext context = new CapsuleContext(
                current.dataId(),
                current.ownerId(),
                owner.userId(),
                current.algorithm(),
                current.ownerKeyId(),
                newVersion,
                policyHash
        );
        byte[] dataKey = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        try {
            byte[] aad = AadBuilder.build(context);
            AesGcm.CipherText encrypted = AesGcm.encrypt(dataKey, localPlaintext, aad);
            return current.withOwnerSideEncryptedVersion(
                    encrypted.ciphertext(),
                    encrypted.nonce(),
                    aad,
                    scheme.encapsulate(dataKey, owner.keyPair().publicKey(), context),
                    newVersion,
                    policyHash,
                    com.example.pre.crypto.hash.Hash.sha256Hex(aad)
            );
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }
}
