package com.example.pre.scenario;

import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.User;
import com.example.pre.service.AuthorizationService;
import com.example.pre.service.DataSecurityService;
import com.example.pre.service.DemoPrivateKeyStore;
import com.example.pre.service.ObjectAuthorizationService;
import com.example.pre.service.ProxyReEncryptionService;
import com.example.pre.service.UserService;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryReEncryptedPackageRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataSharingScenarioTest {
    @Test
    void rsaScenarioWorksEndToEnd() {
        runScenario(new RsaPreScheme(RsaCommonModulusParameters.generate(1024)));
    }

    @Test
    void eccScenarioWorksEndToEnd() {
        runScenario(new EccPreScheme());
    }

    private static void runScenario(PreScheme scheme) {
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        InMemoryGrantRepository grantRepository = new InMemoryGrantRepository();
        InMemoryReEncryptedPackageRepository packageRepository = new InMemoryReEncryptedPackageRepository();
        UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        DataSecurityService data = new DataSecurityService(scheme, dataRepository, audit);
        AuthorizationService authorization = new AuthorizationService(scheme, audit, grantRepository);
        ObjectAuthorizationService objectAuth = new ObjectAuthorizationService(dataRepository, grantRepository, packageRepository, audit);
        ProxyReEncryptionService proxy = new ProxyReEncryptionService(scheme, dataRepository, grantRepository, packageRepository, objectAuth, audit);

        User alice = users.createUser("Alice");
        User bob = users.createUser("Bob");
        User charlie = users.createUser("Charlie");
        byte[] plaintext = Bytes.utf8("sensitive shared document");

        EncryptedDataPackage uploaded = data.upload(alice, plaintext);
        assertFalse(new String(uploaded.encryptedContent()).contains("sensitive shared document"));
        assertArrayEquals(plaintext, data.decryptOriginal(alice, uploaded));
        assertThrows(RuntimeException.class, () -> data.decryptOriginal(bob, uploaded));

        AccessPolicy policy = AccessPolicy.normal(Instant.now().plus(1, ChronoUnit.DAYS));
        var grant = createGrant(scheme, authorization, alice, bob, uploaded, policy);
        ReEncryptedPackage reEncrypted = proxy.reEncrypt("proxy", grant.grantId());
        assertArrayEquals(plaintext, data.decryptReEncrypted(bob, reEncrypted));
        assertThrows(RuntimeException.class, () -> data.decryptReEncrypted(charlie, reEncrypted));

        List<String> actions = audit.findAll().stream().map(event -> event.action()).toList();
        assertTrue(actions.contains("KEYGEN"));
        assertTrue(actions.contains("UPLOAD_ENCRYPTED"));
        assertTrue(actions.contains("GRANT_CREATE"));
        assertTrue(actions.contains("PROXY_REENCRYPT"));
    }

    private static com.example.pre.model.ShareGrant createGrant(
            PreScheme scheme,
            AuthorizationService authorization,
            User alice,
            User bob,
            EncryptedDataPackage uploaded,
            AccessPolicy policy
    ) {
        if (scheme instanceof EccPreScheme) {
            var context = com.example.pre.crypto.ecc.ReKeySessionContext.create();
            return authorization.createGrantWithRecipientShare(
                    alice,
                    bob,
                    uploaded,
                    policy,
                    DemoPrivateKeyStore.createEccRecipientShareLocally(bob, context),
                    context);
        }
        return authorization.createGrant(alice, bob, uploaded, policy);
    }
}
