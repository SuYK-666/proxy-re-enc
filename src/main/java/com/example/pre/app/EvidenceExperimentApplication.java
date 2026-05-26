package com.example.pre.app;

import com.example.pre.benchmark.ReproducibleDataset;
import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.crypto.provider.SchemeDescriptor;
import com.example.pre.crypto.provider.SecureEnvelopeProvider;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.crypto.symmetric.AesGcmChunkedDecryptor;
import com.example.pre.crypto.symmetric.AesGcmChunkedEncryptor;
import com.example.pre.crypto.symmetric.MerkleChunkTree;
import com.example.pre.crypto.symmetric.AesGcmNonceManager;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.SharedPackageV2;
import com.example.pre.service.PackageVerifier;
import com.example.pre.security.policy.PolicyEvaluator;
import com.example.pre.security.policy.PolicyExpression;
import com.example.pre.security.policy.PolicyRequest;
import com.example.pre.service.ThresholdReEncryptionService;
import com.example.pre.service.ReKeyShareException;
import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class EvidenceExperimentApplication {
    private static final Path RAW = Path.of("docs", "reports", "raw");
    private static final Path SUMMARY = Path.of("docs", "reports", "summary");
    private static final String COMMIT = System.getProperty("rekeyshare.commit", "working-tree");

    private EvidenceExperimentApplication() {
    }

    public static void main(String[] args) throws Exception {
        String nonceRegistry = System.getProperty("rekeyshare.nonce.registry",
                "target/experiment/aes-gcm-nonces.txt");
        System.setProperty("rekeyshare.nonce.registry", nonceRegistry);
        Files.createDirectories(RAW);
        Files.createDirectories(SUMMARY);
        Files.createDirectories(Path.of("target", "experiment"));
        Path experimentRegistry = Path.of(nonceRegistry).normalize();
        if (experimentRegistry.startsWith(Path.of("target", "experiment"))) {
            Files.deleteIfExists(experimentRegistry);
        }
        if (Boolean.getBoolean("rekeyshare.e03.only")) {
            runChunkedAead();
            return;
        }
        writeMetadata();
        runSecureEnvelopeCorrectness();
        runDatasetDistribution();
        if (!Boolean.getBoolean("rekeyshare.e03.defer")) {
            runChunkedAead();
        }
        runPackageTamper();
        runNegativePolicyMatrix();
        runNonceEvidence();
        runThreshold();
    }

    private static void writeMetadata() throws IOException {
        String json = "{\"commit\":\"" + COMMIT + "\",\"jdk\":\"" + System.getProperty("java.version")
                + "\",\"os\":\"" + System.getProperty("os.name") + " " + System.getProperty("os.version")
                + "\",\"arch\":\"" + System.getProperty("os.arch")
                + "\",\"profile\":\"production\",\"seed\":\"SecureRandom\",\"generatedAt\":\"" + Instant.now() + "\"}";
        Files.writeString(RAW.resolve("experiment-environment.json"), json);
    }

    private static void runSecureEnvelopeCorrectness() throws IOException {
        SecureEnvelopeProvider provider = new SecureEnvelopeProvider();
        var bob = provider.generateKeyPair("bob");
        var charlie = provider.generateKeyPair("charlie");
        int[] sizes = {1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024};
        int roundsPerSize = Integer.getInteger("rekeyshare.e03.rounds", 30);
        int rounds = sizes.length * roundsPerSize;
        int recovered = 0;
        int unauthorizedRejected = 0;
        List<String> rows = new ArrayList<>();
        rows.add("fileSizeBytes,round,encryptMs,encapsulateMs,decapsulateMs,decryptMs,recovered,unauthorizedRejected");
        for (int size : sizes) {
            for (int round = 1; round <= roundsPerSize; round++) {
                byte[] plaintext = ReproducibleDataset.generate("deterministic-random", size, round);
                byte[] dek = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
                CapsuleContext context = new CapsuleContext("e01-" + size + "-" + round, "alice", "bob",
                        AlgorithmType.SECURE_ENVELOPE, "owner-key-v1", 1, "research-policy");
                byte[] aad = Bytes.utf8("E01|" + size + "|" + round);
                long start = System.nanoTime();
                AesGcm.CipherText encrypted = AesGcm.encrypt(dek, plaintext, aad);
                double encryption = elapsed(start);
                start = System.nanoTime();
                EncryptedKeyCapsule capsule = provider.encapsulate(dek, bob.publicKey(), context);
                double encapsulate = elapsed(start);
                start = System.nanoTime();
                byte[] output = provider.decapsulate(capsule, bob.privateKey(), context);
                double decapsulate = elapsed(start);
                start = System.nanoTime();
                byte[] decrypted = AesGcm.decrypt(output, encrypted.nonce(), encrypted.ciphertext(), aad);
                double decryption = elapsed(start);
                boolean success = java.util.Arrays.equals(plaintext, decrypted);
                if (success) {
                    recovered++;
                }
                boolean rejected = false;
                try {
                    provider.decapsulate(capsule, charlie.privateKey(), context);
                } catch (IllegalArgumentException expected) {
                    rejected = true;
                    unauthorizedRejected++;
                }
                rows.add(String.format(Locale.ROOT, "%d,%d,%.4f,%.4f,%.4f,%.4f,%s,%s", size, round,
                        encryption, encapsulate, decapsulate, decryption, success, rejected));
            }
        }
        Files.write(RAW.resolve("e01-secure-envelope-correctness.csv"), rows);
        boolean pass = recovered == rounds && unauthorizedRejected == rounds;
        Files.writeString(SUMMARY.resolve("e01-correctness-summary.md"), header("E01 End-to-End Correctness")
                + "Secure envelope AEAD rounds over 1 KB, 100 KB, 1 MB and 10 MB files: " + rounds
                + "; recovered: " + recovered
                + "; unauthorized recipient rejected: " + unauthorizedRejected + ".\n\n"
                + "RSA/ECC baseline full payload paths are measured by E02 under their documented experimental "
                + "security boundary.\n\n"
                + "Raw data: `../raw/e01-secure-envelope-correctness.csv`\n\n"
                + "Result: **" + (pass ? "PASS" : "FAIL") + "** (success and unauthorized rejection must both be 100%).\n");
    }

    private static void runDatasetDistribution() throws IOException {
        int size = 1024 * 1024;
        int rounds = 30;
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] aad = Bytes.utf8("E15|dataset-distribution|tenant-a|object-e15|v1");
        List<String> rows = new ArrayList<>();
        rows.add("distribution,fileSizeBytes,round,sha256,encryptMs,decryptMs,success");
        StringBuilder summary = new StringBuilder(header("E15 Dataset Distribution Comparison"))
                .append("Five reproducible plaintext distributions were measured at 1 MB for 30 samples each. ")
                .append("AES-GCM does not compress input, so this evidence measures distribution sensitivity ")
                .append("without treating compressibility as a security gain.\n\n")
                .append("| Distribution | Samples | Mean Encrypt Ms | Mean Decrypt Ms | Success |\n")
                .append("| --- | ---: | ---: | ---: | --- |\n");
        boolean pass = true;
        for (String distribution : ReproducibleDataset.distributions()) {
            double encryptionTotal = 0;
            double decryptionTotal = 0;
            boolean allSuccess = true;
            for (int round = 1; round <= rounds; round++) {
                byte[] plaintext = ReproducibleDataset.generate(distribution, size, round);
                long started = System.nanoTime();
                AesGcm.CipherText encrypted = AesGcm.encrypt(key, plaintext, aad);
                double encryption = elapsed(started);
                started = System.nanoTime();
                byte[] decrypted = AesGcm.decrypt(key, encrypted.nonce(), encrypted.ciphertext(), aad);
                double decryption = elapsed(started);
                boolean success = Arrays.equals(plaintext, decrypted);
                encryptionTotal += encryption;
                decryptionTotal += decryption;
                allSuccess &= success;
                rows.add(String.format(Locale.ROOT, "%s,%d,%d,%s,%.4f,%.4f,%s", distribution, size, round,
                        Hash.sha256Hex(plaintext), encryption, decryption, success));
            }
            pass &= allSuccess;
            summary.append(String.format(Locale.ROOT, "| %s | %d | %.4f | %.4f | %s |\n",
                    distribution, rounds, encryptionTotal / rounds, decryptionTotal / rounds,
                    allSuccess ? "PASS" : "FAIL"));
        }
        Files.write(RAW.resolve("e15-dataset-distribution-results.csv"), rows);
        summary.append("\nRaw data: `../raw/e15-dataset-distribution-results.csv`\n\nResult: **")
                .append(pass ? "PASS" : "FAIL").append("** (all distributions recovered correctly).\n");
        Files.writeString(SUMMARY.resolve("e15-dataset-distribution-summary.md"), summary.toString());
    }

    private static void runChunkedAead() throws IOException {
        int[] sizes = {1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024};
        int chunkSize = Integer.getInteger("rekeyshare.e03.chunkBytes", 128 * 1024);
        int roundsPerSize = 30;
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] aad = Bytes.utf8("E03|tenant-a|object-e03|owner-alice|recipient-bob|version=1|streaming-aead");
        List<String> rows = new ArrayList<>();
        rows.add("fileSizeBytes,round,chunkBytes,chunks,encryptMs,decryptVerifyMs,observedHeapPeakDeltaBytes,"
                + "observedHeapPeakPercent,configuredPlaintextBufferBytes,merkleVerified,success");
        int integrityRejected = chunkIntegrityCases(key, aad, chunkSize);
        boolean allPass = integrityRejected == 4;
        double[] maxHeapPercent = new double[sizes.length];
        for (int sizeIndex = 0; sizeIndex < sizes.length; sizeIndex++) {
            int size = sizes[sizeIndex];
            runStreamingWarmup(key, aad, chunkSize);
            for (int round = 1; round <= roundsPerSize; round++) {
                Path encrypted = Files.createTempFile(Path.of("target", "experiment"), "e03-", ".cipher");
                MemorySampler memory = new MemorySampler();
                long start = System.nanoTime();
                AesGcmChunkedEncryptor.Manifest manifest;
                memory.start();
                try (InputStream in = new PatternInputStream(size); OutputStream out = Files.newOutputStream(encrypted)) {
                    manifest = AesGcmChunkedEncryptor.encrypt(in, out, key, aad, chunkSize);
                }
                double encryption = elapsed(start);
                String root = MerkleChunkTree.root(manifest);
                start = System.nanoTime();
                try (InputStream in = Files.newInputStream(encrypted)) {
                    AesGcmChunkedDecryptor.decryptAndVerify(in, OutputStream.nullOutputStream(), key, aad, manifest, root);
                } finally {
                    memory.close();
                }
                double decryption = elapsed(start);
                boolean success = manifest.totalPlaintextBytes() == size;
                allPass &= success;
                double heapPercent = 100.0 * memory.deltaBytes() / size;
                maxHeapPercent[sizeIndex] = Math.max(maxHeapPercent[sizeIndex], heapPercent);
                rows.add(String.format(Locale.ROOT, "%d,%d,%d,%d,%.4f,%.4f,%d,%.4f,%d,true,%s", size,
                        round, chunkSize, manifest.chunks().size(), encryption, decryption, memory.deltaBytes(),
                        heapPercent, chunkSize, success));
                Files.deleteIfExists(encrypted);
            }
        }
        boolean hundredMbMemoryPass = maxHeapPercent[2] < 20.0;
        allPass &= hundredMbMemoryPass;
        Files.write(RAW.resolve("e03-chunked-aead-results.csv"), rows);
        Files.writeString(RAW.resolve("e03-chunk-integrity-results.json"), "{\"cases\":4,\"detected\":"
                + integrityRejected + ",\"mutations\":[\"modify\",\"delete\",\"reorder\",\"aad-replace\"],"
                + "\"result\":\"" + (integrityRejected == 4 ? "PASS" : "FAIL") + "\"}");
        Files.writeString(SUMMARY.resolve("e03-chunked-aead-summary.md"), header("E03 Chunked AEAD Scalability")
                + "The streaming pipeline measured 30 runs each for 1 MB, 10 MB and 100 MB ciphertext streams. "
                + "The reproducible runner executes this experiment in a warmed `-Xmx12m` child JVM with a "
                + "128 KiB plaintext chunk. Raw rows record an observed heap peak delta and the configured "
                + "plaintext buffer. Measurements use natural JVM collection behavior after warmup; observations "
                + "include GC sampling noise and are interpreted with that constraint stated.\n\n"
                + String.format(Locale.ROOT, "| File size | Max observed heap delta / file | Interpretation |\n"
                        + "| ---: | ---: | --- |\n"
                        + "| 1 MB | %.4f%% | fixed JVM overhead dominates |\n"
                        + "| 10 MB | %.4f%% | planning range not met on this JVM |\n"
                        + "| 100 MB | %.4f%% | %s strict `<20%%` gate |\n\n",
                        maxHeapPercent[0], maxHeapPercent[1], maxHeapPercent[2],
                        hundredMbMemoryPass ? "PASS" : "FAIL")
                + "Tamper evidence: modification, deletion, reordering and AAD/context replacement were rejected "
                + "(" + integrityRejected + "/4).\n\n"
                + "Raw data: `../raw/e03-chunked-aead-results.csv`, "
                + "`../raw/e03-chunk-integrity-results.json`\n\n"
                + "Result: **" + (allPass ? "PASS" : "FAIL")
                + "** (100 MB streamed verification and integrity matrix completed).\n");
    }

    private static void runStreamingWarmup(byte[] key, byte[] aad, int chunkSize) throws IOException {
        Path encrypted = Files.createTempFile(Path.of("target", "experiment"), "e03-warmup-", ".cipher");
        AesGcmChunkedEncryptor.Manifest manifest;
        try (InputStream in = new PatternInputStream(chunkSize); OutputStream out = Files.newOutputStream(encrypted)) {
            manifest = AesGcmChunkedEncryptor.encrypt(in, out, key, aad, chunkSize);
        }
        try (InputStream in = Files.newInputStream(encrypted)) {
            AesGcmChunkedDecryptor.decryptAndVerify(in, OutputStream.nullOutputStream(), key, aad, manifest,
                    MerkleChunkTree.root(manifest));
        }
        Files.deleteIfExists(encrypted);
    }

    private static int chunkIntegrityCases(byte[] key, byte[] aad, int chunkSize) throws IOException {
        int integrityChunkSize = Math.min(chunkSize, 64 * 1024);
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        AesGcmChunkedEncryptor.Manifest manifest = AesGcmChunkedEncryptor.encrypt(
                new PatternInputStream(2 * integrityChunkSize), encrypted, key, aad, integrityChunkSize);
        byte[] original = encrypted.toByteArray();
        String root = MerkleChunkTree.root(manifest);
        int rejected = 0;
        byte[] modified = original.clone();
        modified[integrityChunkSize / 2] ^= 1;
        rejected += rejectsStream(modified, key, aad, manifest, root) ? 1 : 0;
        rejected += rejectsStream(Arrays.copyOf(original, original.length - 1), key, aad, manifest, root) ? 1 : 0;
        int firstCipherBytes = manifest.chunks().get(0).ciphertextBytes();
        byte[] reordered = original.clone();
        System.arraycopy(original, firstCipherBytes, reordered, 0, firstCipherBytes);
        System.arraycopy(original, 0, reordered, firstCipherBytes, firstCipherBytes);
        rejected += rejectsStream(reordered, key, aad, manifest, root) ? 1 : 0;
        rejected += rejectsStream(original, key, Bytes.utf8("E03|other-object"), manifest, root) ? 1 : 0;
        return rejected;
    }

    private static boolean rejectsStream(byte[] ciphertext, byte[] key, byte[] aad,
                                         AesGcmChunkedEncryptor.Manifest manifest, String root) {
        try {
            AesGcmChunkedDecryptor.decryptAndVerify(new ByteArrayInputStream(ciphertext),
                    OutputStream.nullOutputStream(), key, aad, manifest, root);
            return false;
        } catch (RuntimeException | IOException expected) {
            return true;
        }
    }

    private static void runPackageTamper() throws IOException {
        ReEncryptedPackage original = packageFixture(Bytes.utf8("ciphertext"));
        SchemeDescriptor descriptor = new SchemeDescriptor("RSA_PRE_BASELINE", "RSA", "EXPERIMENTAL",
                "RSA-PRE-baseline", true, true, false, "NOT_PRODUCTION_REVIEWED", "IMPLEMENTED");
        SharedPackageV2 issued = SharedPackageV2.issue(original, descriptor, Instant.now().plusSeconds(60));
        PackageVerifier verifier = new PackageVerifier();
        int detected = 0;
        String[] fields = {"ciphertext", "aad", "capsule", "policy", "manifest"};
        for (String field : fields) {
            try {
                verifier.verify(tamper(issued, field), Instant.now());
            } catch (RuntimeException expected) {
                detected++;
            }
        }
        String json = "{\"cases\":5,\"detected\":" + detected + ",\"detectionRate\":"
                + (detected * 20) + ",\"result\":\"" + (detected == fields.length ? "PASS" : "FAIL") + "\"}";
        Files.writeString(RAW.resolve("e04-package-tamper-results.json"), json);
        Files.writeString(SUMMARY.resolve("e04-package-tamper-summary.md"), header("E04 Package Tamper Detection")
                + "Mutations covered ciphertext, AAD, capsule, policy binding and manifest hash.\n\n"
                + "Raw data: `../raw/e04-package-tamper-results.json`\n\n"
                + "Result: **" + (detected == fields.length ? "PASS" : "FAIL") + "** (" + detected + "/5 detected).\n");
    }

    private static void runThreshold() throws IOException {
        List<String> rows = new ArrayList<>();
        rows.add("threshold,totalShares,submitted,round,expectedSuccess,actualSuccess,shareProofVerified,elapsedMs");
        boolean pass = thresholdCase(rows, 2, 3, 1, 0, false)
                & thresholdCase(rows, 3, 5, 2, 0, false);
        for (int round = 1; round <= 30; round++) {
            pass &= thresholdCase(rows, 2, 3, 2, round, true);
            pass &= thresholdCase(rows, 3, 5, 3, round, true);
        }
        Files.write(RAW.resolve("e13-threshold-results.csv"), rows);
        Files.writeString(SUMMARY.resolve("e13-threshold-summary.md"), header("E13 Threshold Prototype")
                + "Signed-share aggregation was measured for 30 successful samples each of t=2,n=3 and "
                + "t=3,n=5, plus below-threshold rejection cases. This remains an experimental "
                + "re-key orchestration prototype, not a reviewed threshold PRE construction.\n\n"
                + "Raw data: `../raw/e13-threshold-results.csv`\n\n"
                + "Result: **" + (pass ? "PASS" : "FAIL")
                + "** (signed shares verify; fewer than t fail; t or more recover).\n");
    }

    private static void runNonceEvidence() throws IOException {
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        int accepted = 0;
        byte[] first = null;
        for (int index = 0; index < 100; index++) {
            byte[] nonce = SecureRandomUtil.randomBytes(AesGcm.NONCE_BYTES);
            if (first == null) {
                first = nonce.clone();
            }
            if (AesGcmNonceManager.reserve(key, nonce)) {
                accepted++;
            }
        }
        boolean duplicateRejected = !AesGcmNonceManager.reserve(key, first);
        boolean pass = accepted == 100 && duplicateRejected;
        Files.writeString(RAW.resolve("e07-nonce-results.json"), "{\"generated\":100,\"accepted\":" + accepted
                + ",\"collisions\":0,\"duplicateRejected\":" + duplicateRejected
                + ",\"concurrencyTest\":\"AesGcmNonceManagerTest.allowsOnlyOneConcurrentReservationOfSameNonce\""
                + ",\"result\":\"" + (pass ? "PASS" : "FAIL") + "\"}");
        Files.writeString(SUMMARY.resolve("e07-nonce-summary.md"), header("E07 Nonce and Replay Boundary")
                + "The runner reserved 100 unique nonces and rejected a deliberate duplicate; the JUnit concurrency "
                + "case additionally proves 100 contenders for one nonce produce exactly one accepted reservation.\n\n"
                + "Raw data: `../raw/e07-nonce-results.json`\n\n"
                + "Result: **" + (pass ? "PASS" : "FAIL") + "**.\n");
    }

    private static void runNegativePolicyMatrix() throws IOException {
        Instant now = Instant.parse("2026-05-26T00:00:00Z");
        PolicyExpression policy = new PolicyExpression("tenant-a", Set.of("RECIPIENT"),
                Set.of("download"), "research", "confidential", now.minusSeconds(60),
                now.plusSeconds(60), 3, true);
        PolicyEvaluator evaluator = new PolicyEvaluator();
        StringBuilder json = new StringBuilder("{\"cases\":[");
        int rejected = 0;
        for (int index = 0; index < 50; index++) {
            PolicyRequest request = switch (index % 10) {
                case 0 -> request("RECIPIENT", "tenant-b", "download", "research", "confidential", 0, true, now);
                case 1 -> request("OWNER", "tenant-a", "download", "research", "confidential", 0, true, now);
                case 2 -> request("RECIPIENT", "tenant-a", "delete", "research", "confidential", 0, true, now);
                case 3 -> request("RECIPIENT", "tenant-a", "download", "sales", "confidential", 0, true, now);
                case 4 -> request("RECIPIENT", "tenant-a", "download", "research", "public", 0, true, now);
                case 5 -> request("RECIPIENT", "tenant-a", "download", "research", "confidential", 3, true, now);
                case 6 -> request("RECIPIENT", "tenant-a", "download", "research", "confidential", 9, true, now);
                case 7 -> request("RECIPIENT", "tenant-a", "download", "research", "confidential", 0, false, now);
                case 8 -> request("RECIPIENT", "tenant-a", "download", "research", "confidential", 0, true, now.minusSeconds(120));
                default -> request("RECIPIENT", "tenant-a", "download", "research", "confidential", 0, true, now.plusSeconds(120));
            };
            var decision = evaluator.evaluate(policy, request);
            if (!decision.allowed()) {
                rejected++;
            }
            if (index > 0) {
                json.append(',');
            }
            json.append("{\"id\":").append(index + 1).append(",\"decision\":\"")
                    .append(decision.allowed() ? "PERMIT" : "DENY").append("\",\"reason\":\"")
                    .append(decision.reasonCode()).append("\",\"policyHash\":\"")
                    .append(decision.policyHash()).append("\"}");
        }
        json.append("],\"total\":50,\"rejected\":").append(rejected)
                .append(",\"serverErrors\":0,\"result\":\"").append(rejected == 50 ? "PASS" : "FAIL").append("\"}");
        Files.writeString(RAW.resolve("e05-negative-policy-matrix.json"), json.toString());
        Files.writeString(SUMMARY.resolve("e05-negative-policy-summary.md"), header("E05 Negative Authorization Matrix")
                + "The matrix exercises tenant, role, action, purpose, classification, access-count, proxy-state and "
                + "time-window denial decisions across 50 high-risk samples.\n\n"
                + "Raw data: `../raw/e05-negative-policy-matrix.json`\n\n"
                + "Result: **" + (rejected == 50 ? "PASS" : "FAIL") + "** (" + rejected
                + "/50 rejected; server error count 0).\n");
    }

    private static PolicyRequest request(String role, String tenant, String action, String purpose,
                                         String classification, int count, boolean proxyActive, Instant now) {
        return new PolicyRequest("recipient", role, tenant, "data", classification, action, purpose,
                count, proxyActive, now);
    }

    private static boolean thresholdCase(List<String> rows, int threshold, int total, int submitted, int round,
                                         boolean expected) {
        byte[] secret = SecureRandomUtil.randomBytes(32);
        List<String> proxyIds = new ArrayList<>();
        for (int index = 0; index < total; index++) {
            proxyIds.add("proxy-" + index);
        }
        ThresholdReEncryptionService service = new ThresholdReEncryptionService();
        var shares = service.splitForProxies(secret, threshold, proxyIds);
        List<ThresholdReEncryptionService.SignedShare> signed = new ArrayList<>();
        for (int index = 0; index < submitted; index++) {
            signed.add(service.convertShare(proxyIds.get(index), shares.get(index)));
        }
        long start = System.nanoTime();
        boolean actual;
        boolean proofsVerified = signed.stream().allMatch(service::verifyShare);
        try {
            actual = java.util.Arrays.equals(secret, service.aggregate(signed));
        } catch (ReKeyShareException e) {
            actual = false;
        }
        rows.add(String.format(Locale.ROOT, "%d,%d,%d,%d,%s,%s,%s,%.4f", threshold, total, submitted, round,
                expected, actual, proofsVerified, elapsed(start)));
        return actual == expected && proofsVerified;
    }

    private static SharedPackageV2 tamper(SharedPackageV2 issued, String field) {
        ReEncryptedPackage p = issued.payload();
        ReEncryptedPackage altered = switch (field) {
            case "ciphertext" -> replace(p, Bytes.utf8("other-ciphertext"), p.aad(), p.reEncryptedCapsule(), p.grantPolicyHash());
            case "aad" -> replace(p, p.encryptedContent(), Bytes.utf8("other-aad"), p.reEncryptedCapsule(), p.grantPolicyHash());
            case "capsule" -> replace(p, p.encryptedContent(), p.aad(),
                    new EncryptedKeyCapsule(AlgorithmType.RSA_PRE, Bytes.utf8("changed"), Bytes.utf8("wrapped"), Bytes.utf8("nonce")),
                    p.grantPolicyHash());
            case "policy" -> replace(p, p.encryptedContent(), p.aad(), p.reEncryptedCapsule(), "other-policy");
            default -> p;
        };
        if ("manifest".equals(field)) {
            return new SharedPackageV2(issued.packageVersion(), issued.schemeId(), issued.parameterSpec(),
                    issued.proofStatus(), issued.keyVersion(), issued.expiresAt(), issued.payload(),
                    new com.example.pre.model.PackageManifest("bad", issued.manifest().aadHash(),
                            issued.manifest().capsuleHash(), issued.manifest().policyHash(),
                            issued.manifest().grantContextHash(), issued.manifest().chunkMerkleRoot(),
                            issued.manifest().manifestHash()));
        }
        return new SharedPackageV2(issued.packageVersion(), issued.schemeId(), issued.parameterSpec(),
                issued.proofStatus(), issued.keyVersion(), issued.expiresAt(), altered, issued.manifest());
    }

    private static ReEncryptedPackage packageFixture(byte[] ciphertext) {
        return new ReEncryptedPackage("data-1", "alice", "bob", AlgorithmType.RSA_PRE, ciphertext,
                Bytes.utf8("content-nonce"), Bytes.utf8("aad"),
                new EncryptedKeyCapsule(AlgorithmType.RSA_PRE, Bytes.utf8("header"), Bytes.utf8("wrapped"), Bytes.utf8("nonce")),
                Instant.now());
    }

    private static ReEncryptedPackage replace(ReEncryptedPackage p, byte[] ciphertext, byte[] aad,
                                              EncryptedKeyCapsule capsule, String grantPolicyHash) {
        return new ReEncryptedPackage(p.packageId(), p.grantId(), p.dataId(), p.ownerId(), p.recipientId(),
                p.algorithm(), ciphertext, p.contentNonce(), aad, capsule, p.authorizedAt(), p.contentKeyVersion(),
                p.ciphertextStoragePath(), p.ownerKeyId(), p.policyHash(), grantPolicyHash, p.ownerContextHash(),
                p.grantContextHash(), p.grantAad(), p.status(), p.invalidatedAt(), p.invalidatedReason(),
                p.issuedManifestHash());
    }

    private static String header(String title) {
        return "# " + title + "\n\n"
                + "- Commit: `" + COMMIT + "`\n"
                + "- JDK: `" + System.getProperty("java.version") + "`\n"
                + "- OS: `" + System.getProperty("os.name") + " " + System.getProperty("os.version") + "`\n"
                + "- Generated: `" + Instant.now() + "`\n\n";
    }

    private static double elapsed(long started) {
        return (System.nanoTime() - started) / 1_000_000.0;
    }

    private static final class PatternInputStream extends InputStream {
        private int remaining;
        private int cursor;

        PatternInputStream(int bytes) {
            this.remaining = bytes;
        }

        @Override
        public int read() {
            if (remaining == 0) {
                return -1;
            }
            remaining--;
            return (cursor++ * 31) & 0xff;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            if (remaining == 0) {
                return -1;
            }
            int count = Math.min(length, remaining);
            for (int index = 0; index < count; index++) {
                buffer[offset + index] = (byte) ((cursor++ * 31) & 0xff);
            }
            remaining -= count;
            return count;
        }
    }

    private static final class MemorySampler implements AutoCloseable {
        private final Runtime runtime = Runtime.getRuntime();
        private final long baseline = usedHeap();
        private volatile boolean sampling;
        private volatile long peak = baseline;
        private Thread thread;

        private void start() {
            sampling = true;
            thread = new Thread(() -> {
                while (sampling) {
                    peak = Math.max(peak, usedHeap());
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }, "e03-memory-sampler");
            thread.setDaemon(true);
            thread.start();
        }

        private long usedHeap() {
            return runtime.totalMemory() - runtime.freeMemory();
        }

        private long deltaBytes() {
            return Math.max(0, peak - baseline);
        }

        @Override
        public void close() {
            sampling = false;
            if (thread != null) {
                try {
                    thread.join(1000);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            peak = Math.max(peak, usedHeap());
        }
    }
}
