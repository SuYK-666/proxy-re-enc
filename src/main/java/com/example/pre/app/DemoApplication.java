package com.example.pre.app;

import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.User;
import com.example.pre.service.AuthorizationService;
import com.example.pre.service.DataSecurityService;
import com.example.pre.service.UserService;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class DemoApplication {
    private DemoApplication() {
    }

    public static void main(String[] args) throws Exception {
        Files.createDirectories(Path.of("demo/output"));
        List<String> lines = new ArrayList<>();
        lines.addAll(runScenario(new RsaPreScheme(RsaCommonModulusParameters.generate(2048))));
        lines.add("");
        lines.addAll(runScenario(new EccPreScheme()));
        Files.write(Path.of("demo/output/demo-result.txt"), lines);
        lines.forEach(System.out::println);
    }

    private static List<String> runScenario(PreScheme scheme) {
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        DataSecurityService dataService = new DataSecurityService(scheme, new InMemoryDataRepository(), audit);
        AuthorizationService authorizationService = new AuthorizationService(scheme, audit);

        User alice = users.createUser("Alice");
        User bob = users.createUser("Bob");
        User charlie = users.createUser("Charlie");

        byte[] plaintext = Bytes.utf8("Confidential course project document: PRE protects cloud data sharing.");
        EncryptedDataPackage uploaded = dataService.upload(alice, plaintext);

        boolean bobBefore = canDecryptOriginal(dataService, bob, uploaded);
        ReEncryptedPackage bobPackage = authorizationService.authorize(alice, bob, uploaded);
        byte[] bobPlaintext = dataService.decryptReEncrypted(bob, bobPackage);
        boolean bobAfter = new String(bobPlaintext).equals(new String(plaintext));
        boolean charlieAfter = canDecryptReEncrypted(dataService, charlie, bobPackage);

        List<String> lines = new ArrayList<>();
        lines.add("=== " + scheme.name() + " Scenario ===");
        lines.add("Alice uploads encrypted file: success");
        lines.add("Ciphertext differs from plaintext: " + !new String(uploaded.encryptedContent()).contains("Confidential"));
        lines.add("Bob decrypts before authorization: " + (bobBefore ? "unexpected success" : "failed"));
        lines.add("Proxy re-encrypts capsule: success");
        lines.add("Bob decrypts after authorization: " + (bobAfter ? "success" : "failed"));
        lines.add("Charlie decrypts after Bob authorization: " + (charlieAfter ? "unexpected success" : "failed"));
        lines.add("Recovered plaintext: " + new String(bobPlaintext));
        lines.add("Audit log:");
        for (AuditEvent event : audit.findAll()) {
            lines.add("  " + event.timestamp() + " " + event.actor() + " " + event.action()
                    + " " + event.target() + " success=" + event.success());
        }
        return lines;
    }

    private static boolean canDecryptOriginal(DataSecurityService service, User user, EncryptedDataPackage dataPackage) {
        try {
            service.decryptOriginal(user, dataPackage);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean canDecryptReEncrypted(DataSecurityService service, User user, ReEncryptedPackage dataPackage) {
        try {
            service.decryptReEncrypted(user, dataPackage);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
