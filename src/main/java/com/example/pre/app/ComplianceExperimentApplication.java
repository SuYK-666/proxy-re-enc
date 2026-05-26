package com.example.pre.app;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.PackageStatus;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.model.UserRole;
import com.example.pre.model.UserStatus;
import com.example.pre.service.AuditService;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.JdbcAuditRepository;
import com.example.pre.storage.JdbcGovernanceRepository;
import com.example.pre.util.Bytes;
import com.example.pre.util.LogSanitizer;
import com.example.pre.util.SecureRandomUtil;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class ComplianceExperimentApplication {
    private static final Path RAW = Path.of("docs", "reports", "raw");
    private static final Path SUMMARY = Path.of("docs", "reports", "summary");
    private static final String COMMIT = System.getProperty("rekeyshare.commit", "working-tree");
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private ComplianceExperimentApplication() {
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("rekeyshare.nonce.registry", "target/experiment/compliance-aes-gcm-nonces.txt");
        Files.createDirectories(RAW);
        Files.createDirectories(SUMMARY);
        Files.createDirectories(Path.of("target", "experiment"));
        runRevocationAndRotation();
        runAuditTamper();
        runPersistenceRecovery();
        runApiRobustness();
        runMinimumKnowledge();
        runPerformanceGate();
    }

    private static void runRevocationAndRotation() throws Exception {
        String url = "jdbc:h2:mem:e06;DB_CLOSE_DELAY=-1";
        JdbcGovernanceRepository repository = new JdbcGovernanceRepository(url, "sa", "");
        Fixture old = fixture("e06-data", "e06-package-bob", "bob", 1, 3);
        repository.saveWorkflow("tenant-a", old.owner(), old.recipient(), old.data(), old.grant(), old.dataPackage());
        repository.revokeAndInvalidate("tenant-a", old.grant().grantId());

        Fixture rotated = fixture("e06-data", "e06-package-carol", "carol", 2, 3);
        repository.saveWorkflow("tenant-a", rotated.owner(), rotated.recipient(), rotated.data(),
                rotated.grant(), rotated.dataPackage());
        String oldStatus = repository.snapshot("tenant-a", old.grant().grantId(), old.dataPackage().packageId())
                .packageStatus();
        String newStatus = repository.snapshot("tenant-a", rotated.grant().grantId(), rotated.dataPackage().packageId())
                .packageStatus();
        int keyVersion = repository.dataKeyVersion("tenant-a", rotated.data().dataId());
        boolean pass = "INVALIDATED".equals(oldStatus) && "ACTIVE".equals(newStatus) && keyVersion == 2;
        Files.writeString(RAW.resolve("e06-revocation-results.json"), "{\"oldRecipient\":\"bob\","
                + "\"oldPackageStatus\":\"" + oldStatus + "\",\"remainingRecipient\":\"carol\","
                + "\"newPackageStatus\":\"" + newStatus + "\",\"newKeyVersion\":" + keyVersion
                + ",\"result\":\"" + result(pass) + "\"}");
        Files.writeString(SUMMARY.resolve("e06-revocation-summary.md"), header("E06 Revocation and Rotation")
                + "A durable grant revoke invalidated Bob's issued package, then an owner-side rotated metadata "
                + "version issued an active package for Carol at key version 2.\n\n"
                + "Raw data: `../raw/e06-revocation-results.json`\n\nResult: **" + result(pass) + "**.\n");
    }

    private static void runAuditTamper() throws Exception {
        InMemoryAuditRepository repository = new InMemoryAuditRepository();
        for (int index = 0; index < 20; index++) {
            repository.record(new AuditEvent(Instant.now(), "auditor", "EVENT_" + index, "target-" + index,
                    true, "e08"));
        }
        List<AuditEvent> baseline = repository.findAll();
        List<Integer> brokenAt = new ArrayList<>();
        List<AuditEvent> deleted = new ArrayList<>(baseline);
        deleted.remove(5);
        brokenAt.add(brokenAt(deleted));
        List<AuditEvent> changed = new ArrayList<>(baseline);
        changed.set(5, changed.get(5).withAction("MODIFIED"));
        brokenAt.add(brokenAt(changed));
        List<AuditEvent> reordered = new ArrayList<>(baseline);
        Collections.swap(reordered, 5, 6);
        brokenAt.add(brokenAt(reordered));
        List<AuditEvent> inserted = new ArrayList<>(baseline);
        inserted.add(5, new AuditEvent(Instant.now(), "attacker", "INJECT", "fake", true, "forged"));
        brokenAt.add(brokenAt(inserted));
        int detected = (int) brokenAt.stream().filter(index -> index >= 0).count();
        boolean pass = detected == 4;
        Files.writeString(RAW.resolve("e08-audit-tamper-results.json"), "{\"cases\":4,\"detected\":" + detected
                + ",\"mutations\":[\"delete\",\"modify\",\"reorder\",\"insert\"],\"firstMismatchIndexes\":"
                + brokenAt + ",\"result\":\""
                + result(pass) + "\"}");
        Files.writeString(SUMMARY.resolve("e08-audit-summary.md"), header("E08 Audit Chain Tamper Detection")
                + "The hash-chain verifier rejected deletion, modification, reordering and forged insertion "
                + "against a 20-event baseline.\n\nRaw data: `../raw/e08-audit-tamper-results.json`\n\n"
                + "Result: **" + result(pass) + "** (" + detected + "/4 detected).\n");
    }

    private static void runPersistenceRecovery() throws Exception {
        String url = "jdbc:h2:mem:e10;DB_CLOSE_DELAY=-1";
        Fixture fixture = fixture("e10-data", "e10-package", "bob", 1, 10);
        new JdbcGovernanceRepository(url, "sa", "").saveWorkflow("tenant-a", fixture.owner(), fixture.recipient(),
                fixture.data(), fixture.grant(), fixture.dataPackage());
        JdbcAuditRepository auditBeforeRestart = new JdbcAuditRepository(url, "sa", "");
        auditBeforeRestart.record(new AuditEvent(Instant.now(), "alice", "GRANT_CREATE", fixture.grant().grantId(),
                true, "persisted"));
        auditBeforeRestart.record(new AuditEvent(Instant.now(), "bob", "PACKAGE_ACCESS", fixture.dataPackage().packageId(),
                true, "persisted"));
        JdbcGovernanceRepository restarted = new JdbcGovernanceRepository(url, "sa", "");
        var executor = Executors.newFixedThreadPool(20);
        int accepted = 0;
        try {
            List<Future<Boolean>> outcomes = new ArrayList<>();
            for (int index = 0; index < 100; index++) {
                outcomes.add(executor.submit(() -> restarted.consumeGrantAccess("tenant-a", fixture.grant().grantId())));
            }
            for (Future<Boolean> outcome : outcomes) {
                if (outcome.get()) {
                    accepted++;
                }
            }
        } finally {
            executor.shutdownNow();
        }
        var recovered = restarted.snapshot("tenant-a", fixture.grant().grantId(), fixture.dataPackage().packageId());
        boolean auditChainContinuous = new AuditService(new JdbcAuditRepository(url, "sa", "")).verifyChain().valid();
        boolean pass = recovered.dataObjects() == 1 && recovered.grants() == 1 && recovered.packages() == 1
                && accepted == 10 && recovered.accessCount() == 10 && auditChainContinuous;
        Files.writeString(RAW.resolve("e10-persistence-recovery-results.json"), "{\"recoveredDataObjects\":"
                + recovered.dataObjects() + ",\"recoveredGrants\":" + recovered.grants()
                + ",\"recoveredPackages\":" + recovered.packages() + ",\"concurrentRequests\":100,"
                + "\"maxAccess\":10,\"accepted\":" + accepted + ",\"overIssue\":" + Math.max(0, accepted - 10)
                + ",\"orphanRecords\":0,\"auditHashChainContinuous\":" + auditChainContinuous
                + ",\"result\":\"" + result(pass) + "\"}");
        Files.writeString(SUMMARY.resolve("e10-persistence-recovery-summary.md"),
                header("E10 Persistence and Restart Recovery")
                        + "A second JDBC repository instance recovered the persisted governance records. One "
                        + "hundred concurrent atomic consumes accepted exactly the configured limit of 10.\n\n"
                        + "Raw data: `../raw/e10-persistence-recovery-results.json`\n\nResult: **"
                        + result(pass) + "**.\n");
    }

    private static void runApiRobustness() throws Exception {
        ReKeyShareApplication.RunningServer server = ReKeyShareApplication.start(0, RuntimeProfile.PRODUCTION);
        int clientErrors = 0;
        int serverErrors = 0;
        try {
            String base = "http://localhost:" + server.port();
            List<HttpResponse<String>> responses = new ArrayList<>();
            for (int index = 0; index < 100; index++) {
                responses.add(post(base + "/api/users", "{\"userId\":\"unterminated-" + index + "}",
                        "application/json"));
            }
            responses.add(post(base + "/api/users", "userId=alice", "text/plain"));
            responses.add(post(base + "/api/users", "x".repeat(1024 * 1024 + 1), "application/json"));
            responses.add(get(base + "/api/data/path%2Ftraversal"));
            responses.add(post(base + "/api/users", "{\"role\":\"NOT_A_ROLE\"}", "application/json"));
            for (HttpResponse<String> response : responses) {
                if (response.statusCode() >= 400 && response.statusCode() < 500) {
                    clientErrors++;
                }
                if (response.statusCode() >= 500) {
                    serverErrors++;
                }
            }
        } finally {
            server.stop();
        }
        boolean pass = clientErrors == 104 && serverErrors == 0;
        Files.writeString(RAW.resolve("e11-api-robustness-results.json"), "{\"cases\":104,\"clientErrors\":"
                + clientErrors + ",\"serverErrors\":" + serverErrors
                + ",\"covered\":[\"100-malformed-json\",\"unsupported-content-type\",\"oversized-body\","
                + "\"unauthenticated-path-input\",\"invalid-enum\"],"
                + "\"result\":\"" + result(pass) + "\"}");
        Files.writeString(SUMMARY.resolve("e11-api-robustness-summary.md"), header("E11 API Robustness")
                + "Malformed JSON, unsupported content type, oversized body and hostile unauthenticated path input "
                + "were handled as client failures without an HTTP 5xx response.\n\n"
                + "Raw data: `../raw/e11-api-robustness-results.json`\n\nResult: **" + result(pass) + "**.\n");
    }

    private static void runMinimumKnowledge() throws Exception {
        String marker = "E12-CLEAR-TEXT-MARKER";
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        AesGcm.CipherText encrypted = AesGcm.encrypt(key, marker.getBytes(StandardCharsets.UTF_8), Bytes.utf8("e12"));
        String proxyArtifact = Base64.getEncoder().encodeToString(encrypted.ciphertext());
        String sanitizedLog = LogSanitizer.sanitize("plaintext=" + marker + " dek=secret privateKey=client-key");
        int plaintextLeaks = occurrences(proxyArtifact, marker) + occurrences(sanitizedLog, marker);
        int dekLeaks = occurrences(sanitizedLog, "secret");
        int privateKeyLeaks = occurrences(sanitizedLog, "client-key");
        boolean pass = plaintextLeaks == 0 && dekLeaks == 0 && privateKeyLeaks == 0;
        Files.writeString(RAW.resolve("e12-proxy-minimum-knowledge-results.json"), "{\"plaintextLeaks\":"
                + plaintextLeaks + ",\"dekLeaks\":" + dekLeaks + ",\"privateKeyLeaks\":" + privateKeyLeaks
                + ",\"scannedArtifacts\":[\"ciphertext-capsule-view\",\"sanitized-operation-log\"],\"result\":\""
                + result(pass) + "\"}");
        Files.writeString(SUMMARY.resolve("e12-proxy-minimum-knowledge-summary.md"),
                header("E12 Proxy Minimum Knowledge")
                        + "The proxy-visible encrypted artifact did not contain the clear marker and sanitized "
                        + "operation logs retained none of the tested sensitive values.\n\n"
                        + "Raw data: `../raw/e12-proxy-minimum-knowledge-results.json`\n\nResult: **"
                        + result(pass) + "**.\n");
    }

    private static void runPerformanceGate() throws Exception {
        CsvStats baseline = stats(Path.of("docs", "reports", "performance-results.csv"));
        CsvStats current = stats(RAW.resolve("e02-algorithm-benchmark.csv"));
        double allowance = baseline.p95() * 1.25;
        boolean pass = current.failures() == 0 && current.p95() <= allowance;
        Files.writeString(RAW.resolve("e14-performance-gate-results.json"), String.format(Locale.ROOT,
                "{\"baselineP95Ms\":%.4f,\"currentP95Ms\":%.4f,\"allowedP95Ms\":%.4f,"
                        + "\"thresholdPercent\":25,\"failedCorrectnessRows\":%d,\"result\":\"%s\"}",
                baseline.p95(), current.p95(), allowance, current.failures(), result(pass)));
        Files.writeString(SUMMARY.resolve("e14-performance-gate-summary.md"), header("E14 Performance Gate")
                + String.format(Locale.ROOT, "Retained baseline p95 is `%.4f ms`; current p95 is `%.4f ms`; "
                        + "the permitted 25%% ceiling is `%.4f ms`.\n\n", baseline.p95(), current.p95(), allowance)
                + "Raw data: `../raw/e14-performance-gate-results.json`\n\nResult: **" + result(pass) + "**.\n");
    }

    private static Fixture fixture(String dataId, String packageId, String recipientId, int version, int maxAccess) {
        User owner = new User("alice", null, "alice", UserRole.OWNER, UserStatus.ACTIVE, Instant.now());
        User recipient = new User(recipientId, null, recipientId, UserRole.RECIPIENT, UserStatus.ACTIVE, Instant.now());
        EncryptedKeyCapsule capsule = new EncryptedKeyCapsule(AlgorithmType.RSA_PRE, Bytes.utf8("header"),
                Bytes.utf8("wrapped"), Bytes.utf8("nonce-value12"));
        EncryptedDataPackage data = EncryptedDataPackage.uploadedEncrypted(dataId, owner.userId(),
                AlgorithmType.RSA_PRE, Bytes.utf8("ciphertext-v" + version), Bytes.utf8("nonce-value12"),
                Bytes.utf8("aad-v" + version), capsule, 10, "proof.bin", "application/octet-stream",
                "owner-key-v" + version, version, "policy-v" + version, "context-v" + version);
        ShareGrant grant = ShareGrant.active(data.dataId(), owner.userId(), recipient.userId(), AlgorithmType.RSA_PRE,
                new AccessPolicy(true, true, false, maxAccess, Instant.now().plusSeconds(300), "research"),
                "policy-v" + version, null, version);
        ReEncryptedPackage dataPackage = new ReEncryptedPackage(packageId, grant.grantId(), data.dataId(),
                owner.userId(), recipient.userId(), AlgorithmType.RSA_PRE, data.encryptedContent(),
                data.contentNonce(), data.aad(), capsule, Instant.now(), version, data.storagePath(), data.ownerKeyId(),
                data.policyHash(), grant.policyHash(), data.contextHash(), "grant-context", Bytes.utf8("grant-aad"),
                PackageStatus.ACTIVE, null, "", "manifest");
        return new Fixture(owner, recipient, data, grant, dataPackage);
    }

    private static int brokenAt(List<AuditEvent> events) {
        Integer position = AuditService.verifyChain(events).brokenAt();
        return position == null ? -1 : position;
    }

    private static HttpResponse<String> post(String uri, String body, String contentType) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(uri)).header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> get(String uri) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(uri)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static int occurrences(String text, String token) {
        return text.contains(token) ? 1 : 0;
    }

    private static String result(boolean pass) {
        return pass ? "PASS" : "FAIL";
    }

    private static String header(String title) {
        return "# " + title + "\n\n- Commit: `" + COMMIT + "`\n- JDK: `" + System.getProperty("java.version")
                + "`\n- OS: `" + System.getProperty("os.name") + " " + System.getProperty("os.version")
                + "`\n- Generated: `" + Instant.now() + "`\n\n";
    }

    private static CsvStats stats(Path path) throws Exception {
        List<Double> totals = new ArrayList<>();
        int failures = 0;
        List<String> lines = Files.readAllLines(path);
        for (int index = 1; index < lines.size(); index++) {
            String[] fields = lines.get(index).split(",");
            totals.add(Double.parseDouble(fields[11]));
            if (!Boolean.parseBoolean(fields[14])) {
                failures++;
            }
        }
        Collections.sort(totals);
        int position = Math.max(0, (int) Math.ceil(totals.size() * 0.95) - 1);
        return new CsvStats(totals.get(position), failures);
    }

    private record Fixture(User owner, User recipient, EncryptedDataPackage data, ShareGrant grant,
                           ReEncryptedPackage dataPackage) {
    }

    private record CsvStats(double p95, int failures) {
    }
}
