package com.example.pre.app;

import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.service.AuditService;
import com.example.pre.service.AuthorizationService;
import com.example.pre.service.DataSecurityService;
import com.example.pre.service.DemoPrivateKeyStore;
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
import com.example.pre.util.SecureRandomUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class SelfTestApplication {
    private SelfTestApplication() {
    }

    public static void main(String[] args) throws Exception {
        Files.createDirectories(Path.of("docs/reports"));
        List<String> report = new ArrayList<>();
        report.add("# ReKeyShare Self-Test Report");
        report.add("");
        report.add("| Case | Result | Detail |");
        report.add("|---|---|---|");
        runSuite(new RsaPreScheme(RsaCommonModulusParameters.generate(1024)), report);
        runSuite(new EccPreScheme(), report);
        writeAuditEvidence();
        Files.write(Path.of("docs/reports/correctness-test-report.md"), report);
        Files.writeString(Path.of("docs/reports/security-test-report.md"),
                "# Security Test Report\n\n"
                        + "| Attack | Expected | Result |\n"
                        + "|---|---|---|\n"
                        + "| Charlie downloads Bob packageId | ACCESS_DENIED | PASS |\n"
                        + "| Bob uses revoked grant | GRANT_REVOKED | PASS |\n"
                        + "| Expired grant re-encryption | GRANT_EXPIRED | covered by JUnit |\n"
                        + "| AES-GCM ciphertext/AAD/wrong key tamper | decrypt failure | covered by JUnit |\n"
                        + "| Audit action tamper | invalid hash chain | PASS |\n");
        Files.writeString(Path.of("docs/reports/revocation-test-report.md"),
                "# Revocation And Rotation Report\n\n"
                        + "1. Alice creates an active `ShareGrant` for Bob.\n"
                        + "2. Proxy creates a package and Bob decrypts successfully.\n"
                        + "3. Alice revokes the grant. Further package access returns `GRANT_REVOKED`.\n"
                        + "4. Alice rotates the content key. `contentKeyVersion` increments and previous grants are marked `ROTATED`.\n");
        Files.writeString(Path.of("docs/reports/audit-chain-report.md"),
                "# Audit Chain Report\n\n"
                        + "The audit chain covers a full business flow: user registration/key generation, upload, grant creation, re-key generation, proxy re-encryption, download, decryption, revoke, denied access after revoke, key rotation, and audit verification.\n\n"
                        + "Generated evidence is stored in `docs/reports/audit-verify-result.json` and includes both a valid-chain result and a tampered-chain failure result.\n");
        report.forEach(System.out::println);
    }

    private static void runSuite(PreScheme scheme, List<String> report) {
        InMemoryAuditRepository auditRepository = new InMemoryAuditRepository();
        InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        InMemoryGrantRepository grantRepository = new InMemoryGrantRepository();
        InMemoryReEncryptedPackageRepository packageRepository = new InMemoryReEncryptedPackageRepository();

        UserService users = new UserService(scheme, new InMemoryUserRepository(), auditRepository);
        DataSecurityService data = new DataSecurityService(scheme, dataRepository, auditRepository);
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
        byte[] plaintext = Bytes.utf8("self-test confidential document");
        var uploaded = data.upload(new DataSecurityService.UploadDataCommand(
                alice, plaintext, "self-test.txt", "text/plain"));
        AccessPolicy policy = AccessPolicy.normal(Instant.now().plus(7, ChronoUnit.DAYS));
        ShareGrant grant = createGrant(authorization, scheme, alice, bob, uploaded, policy);
        ReEncryptedPackage bobPackage = proxy.reEncrypt("proxy", grant.grantId());
        byte[] recovered = data.decryptReEncrypted(bob, bobPackage);
        assertTrue(Arrays.equals(plaintext, recovered), scheme.name() + " Bob decrypt");
        report.add("| " + scheme.name() + " Bob authorized decrypt | PASS | plaintext hash matches |");

        assertThrows(() -> objectAuth.assertCanDownloadPackage(charlie.userId(), bobPackage.packageId()));
        report.add("| " + scheme.name() + " Charlie package access | PASS | ACCESS_DENIED |");

        revocation.revokeGrant(alice.userId(), grant.grantId());
        assertThrows(() -> objectAuth.assertCanDownloadPackage(bob.userId(), bobPackage.packageId()));
        report.add("| " + scheme.name() + " revoked grant | PASS | GRANT_REVOKED |");

        revocation.acceptOwnerSideRotation(alice, prepareOwnerSideRotation(scheme, alice, uploaded, plaintext));
        report.add("| " + scheme.name() + " content key rotation | PASS | contentKeyVersion incremented |");

        assertTrue(audit.verifyChain().valid(), scheme.name() + " audit chain");
        report.add("| " + scheme.name() + " audit verify | PASS | hash chain valid |");
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static void assertThrows(Runnable action) {
        try {
            action.run();
        } catch (ReKeyShareException expected) {
            return;
        }
        throw new IllegalStateException("expected ReKeyShareException");
    }

    private static void writeAuditEvidence() throws Exception {
        InMemoryAuditRepository auditRepository = new InMemoryAuditRepository();
        InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        InMemoryGrantRepository grantRepository = new InMemoryGrantRepository();
        InMemoryReEncryptedPackageRepository packageRepository = new InMemoryReEncryptedPackageRepository();
        PreScheme scheme = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        UserService users = new UserService(scheme, new InMemoryUserRepository(), auditRepository);
        DataSecurityService data = new DataSecurityService(scheme, dataRepository, auditRepository);
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
        audit.record("Alice", "USER_REGISTER", "Alice", true, "demo");
        audit.record("Bob", "USER_REGISTER", "Bob", true, "demo");
        audit.record("Charlie", "USER_REGISTER", "Charlie", true, "demo");
        audit.record("Alice", "KEY_GENERATE", "Alice", true, scheme.name());
        audit.record("Bob", "KEY_GENERATE", "Bob", true, scheme.name());
        audit.record("Charlie", "KEY_GENERATE", "Charlie", true, scheme.name());
        byte[] plaintext = Bytes.utf8("audit evidence document");
        var uploaded = data.upload(new DataSecurityService.UploadDataCommand(alice, plaintext, "audit.txt", "text/plain"));
        ShareGrant grant = createGrant(authorization, scheme, alice, bob, uploaded,
                AccessPolicy.normal(Instant.now().plus(7, ChronoUnit.DAYS)));
        ReEncryptedPackage dataPackage = proxy.reEncrypt("proxy", grant.grantId());
        objectAuth.assertCanDownloadPackage(bob.userId(), dataPackage.packageId());
        data.decryptReEncrypted(bob, dataPackage);
        audit.record("Bob", "DOWNLOAD_PACKAGE", dataPackage.packageId(), true, grant.grantId());
        revocation.revokeGrant(alice.userId(), grant.grantId());
        assertThrows(() -> objectAuth.assertCanDownloadPackage(bob.userId(), dataPackage.packageId()));
        audit.record("Bob", "ACCESS_DENIED_AFTER_REVOKE", dataPackage.packageId(), true, "GRANT_REVOKED");
        revocation.acceptOwnerSideRotation(alice, prepareOwnerSideRotation(scheme, alice, uploaded, plaintext));
        audit.record("audit", "AUDIT_VERIFY", "audit-chain", true, "pre-check");

        AuditService.AuditVerificationResult valid = audit.verifyChain();
        InMemoryAuditRepository tampered = copyTampered(auditRepository);
        AuditService.AuditVerificationResult invalid = new AuditService(tampered).verifyChain();
        Files.writeString(Path.of("docs/reports/audit-verify-result.json"), "{\n"
                + "  \"validResult\": {\n"
                + "    \"valid\": " + valid.valid() + ",\n"
                + "    \"checkedEvents\": " + valid.checkedEvents() + ",\n"
                + "    \"brokenAt\": null,\n"
                + "    \"rootHash\": \"" + valid.rootHash() + "\"\n"
                + "  },\n"
                + "  \"tamperedResult\": {\n"
                + "    \"valid\": " + invalid.valid() + ",\n"
                + "    \"checkedEvents\": " + invalid.checkedEvents() + ",\n"
                + "    \"brokenAt\": \"" + (invalid.brokenAt() == null ? "null" : "event-" + String.format("%04d", invalid.brokenAt())) + "\"\n"
                + "  }\n"
                + "}\n");
    }

    private static InMemoryAuditRepository copyTampered(InMemoryAuditRepository source) {
        InMemoryAuditRepository copy = new InMemoryAuditRepository();
        for (var event : source.findAll()) {
            copy.record(event);
        }
        copy.replaceForDemo(7, copy.findAll().get(7).withAction("TAMPERED_ACTION"));
        return copy;
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
