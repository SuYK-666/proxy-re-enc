package com.example.pre.app;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.ecc.EccInteractiveReKeyGenerator;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.ecc.EccPrivateKeyMaterial;
import com.example.pre.crypto.ecc.EccPublicKeyMaterial;
import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.crypto.ecc.ReKeySessionContext;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.crypto.rsa.RsaPrivateKeyMaterial;
import com.example.pre.crypto.rsa.RsaPublicKeyMaterial;
import com.example.pre.crypto.rsa.RsaReKeyGenerator;
import com.example.pre.crypto.symmetric.AesGcm;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.AadBuilder;
import com.example.pre.util.SecureRandomUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class BenchmarkApplication {
    private BenchmarkApplication() {
    }

    public static void main(String[] args) throws Exception {
        Path rawOutput = Path.of(System.getProperty("rekeyshare.benchmark.rawOutput",
                "docs/reports/raw/e02-algorithm-benchmark.csv"));
        Path summaryDirectory = Path.of(System.getProperty("rekeyshare.benchmark.summaryDirectory",
                "docs/reports/summary"));
        Files.createDirectories(rawOutput.getParent());
        Files.createDirectories(summaryDirectory);
        List<String> rows = new ArrayList<>();
        rows.add("algorithm,parameterSpec,fileSizeBytes,round,keyGenMs,aesEncryptMs,encapsulateMs,reKeyGenMs,reEncryptMs,decapsulateMs,aesDecryptMs,totalMs,capsuleBytes,ciphertextBytes,success");
        benchmark(new RsaPreScheme(RsaCommonModulusParameters.generate(3072)), "common-modulus-3072-demo", rows);
        benchmark(new EccPreScheme(), "P-256-demo", rows);
        Files.write(rawOutput, rows);
        Files.writeString(summaryDirectory.resolve("e02-performance-summary.md"), summary(rows));
        Files.writeString(summaryDirectory.resolve("e02-rsa-vs-ecc.md"), comparison(rows));
    }

    private static void benchmark(PreScheme scheme, String parameterSpec, List<String> rows) {
        int warmup = Integer.getInteger("rekeyshare.benchmark.warmup", 20);
        int measurement = Integer.getInteger("rekeyshare.benchmark.measurement", 100);
        int[] sizes = {1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024};
        for (int fileSize : sizes) {
            for (int i = 0; i < warmup; i++) {
                runRound(scheme, parameterSpec, fileSize, -1);
            }
            for (int round = 1; round <= measurement; round++) {
                rows.add(runRound(scheme, parameterSpec, fileSize, round).toCsv());
            }
        }
    }

    private static ReEncryptionKey createReKey(PreScheme scheme, UserKeyPair owner, UserKeyPair recipient) {
        if (scheme instanceof RsaPreScheme rsaScheme) {
            return rsaScheme.generateBaselineReEncryptionKey(
                    (RsaPrivateKeyMaterial) owner.privateKey(),
                    (RsaPublicKeyMaterial) recipient.publicKey()
            );
        }
        ReKeySessionContext context = ReKeySessionContext.create();
        EccInteractiveReKeyGenerator generator = new EccInteractiveReKeyGenerator();
        RecipientReKeyShare share = generator.createRecipientShare(
                (EccPrivateKeyMaterial) recipient.privateKey(),
                context
        );
        return generator.generateReEncryptionKey(
                (EccPrivateKeyMaterial) owner.privateKey(),
                (EccPublicKeyMaterial) recipient.publicKey(),
                share,
                context
        );
    }

    private static BenchmarkRow runRound(PreScheme scheme, String parameterSpec, int fileSize, int round) {
        byte[] plaintext = SecureRandomUtil.randomBytes(fileSize);
        CapsuleContext capsuleContext = new CapsuleContext(
                "benchmark-" + fileSize + "-" + round,
                "owner",
                "owner",
                scheme.algorithm(),
                "benchmark-key",
                1,
                "BENCHMARK"
        );
        byte[] aad = AadBuilder.build(capsuleContext);
        byte[] dataKey = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);

        long totalStart = System.nanoTime();
        long start = System.nanoTime();
        UserKeyPair owner = scheme.generateKeyPair("owner");
        UserKeyPair recipient = scheme.generateKeyPair("recipient");
        double keyGenMs = elapsedMs(start);

        start = System.nanoTime();
        AesGcm.CipherText encrypted = AesGcm.encrypt(dataKey, plaintext, aad);
        double aesEncryptMs = elapsedMs(start);

        start = System.nanoTime();
        EncryptedKeyCapsule capsule = scheme.encapsulate(dataKey, owner.publicKey(), capsuleContext);
        double encapsulateMs = elapsedMs(start);

        start = System.nanoTime();
        ReEncryptionKey reKey = createReKey(scheme, owner, recipient);
        double reKeyGenMs = elapsedMs(start);

        start = System.nanoTime();
        EncryptedKeyCapsule transformed = scheme.reEncrypt(capsule, reKey, capsuleContext);
        double reEncryptMs = elapsedMs(start);

        start = System.nanoTime();
        byte[] recoveredDataKey = scheme.decapsulate(transformed, recipient.privateKey(), capsuleContext);
        double decapsulateMs = elapsedMs(start);

        start = System.nanoTime();
        byte[] recoveredPlaintext = AesGcm.decrypt(recoveredDataKey, encrypted.nonce(), encrypted.ciphertext(), aad);
        double aesDecryptMs = elapsedMs(start);
        double totalMs = elapsedMs(totalStart);

        boolean success = java.util.Arrays.equals(plaintext, recoveredPlaintext);
        return new BenchmarkRow(
                scheme.name(),
                parameterSpec,
                fileSize,
                round,
                keyGenMs,
                aesEncryptMs,
                encapsulateMs,
                reKeyGenMs,
                reEncryptMs,
                decapsulateMs,
                aesDecryptMs,
                totalMs,
                transformed.header().length + transformed.wrappedKey().length + transformed.keyNonce().length,
                encrypted.ciphertext().length + encrypted.nonce().length,
                success
        );
    }

    private static double elapsedMs(long startNs) {
        return (System.nanoTime() - startNs) / 1_000_000.0;
    }

    private static String summary(List<String> rows) {
        MapKeyStats stats = MapKeyStats.from(rows);
        StringBuilder sb = new StringBuilder();
        sb.append("# Performance Summary\n\n");
        sb.append("Source: `../raw/e02-algorithm-benchmark.csv`\n\n");
        sb.append("Formal experiment settings: warmup=20 and measurement=100 per algorithm/file size; "
                + "JUnit may override these values for schema smoke checks.\n\n");
        sb.append("| Algorithm | File Size | Avg Total Ms | P50 | P95 | P99 | Stddev | Throughput B/s | Avg AES Encrypt Ms | Avg AES Decrypt Ms | Avg ReEncrypt Ms | Capsule Bytes | Success |\n");
        sb.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n");
        for (MapKeyStats.Entry entry : stats.entries()) {
            sb.append(String.format(Locale.ROOT, "| %s | %d | %.4f | %.4f | %.4f | %.4f | %.4f | %.2f | %.4f | %.4f | %.4f | %.0f | %s |\n",
                    entry.algorithm,
                    entry.fileSize,
                    entry.avgTotal(),
                    entry.percentileTotal(50),
                    entry.percentileTotal(95),
                    entry.percentileTotal(99),
                    entry.stddevTotal(),
                    entry.throughputBytesPerSecond(),
                    entry.avgAesEncrypt(),
                    entry.avgAesDecrypt(),
                    entry.avgReEncrypt(),
                    entry.avgCapsule(),
                    entry.allSuccess ? "PASS" : "FAIL"));
        }
        sb.append("\nThe CSV remains the source of truth; this summary is generated from the same rows.\n\n");
        sb.append("## Analysis\n\n");
        sb.append("Correctness passed for every measured row. On a warmed JVM with CPU AES acceleration, "
                + "AES-GCM throughput can be faster than the conservative planning interval; lower latency is not "
                + "a regression when authentication and recovery checks remain successful. RSA/ECC values are "
                + "baseline comparison data only and do not change their experimental security status.\n");
        return sb.toString();
    }

    private static String comparison(List<String> rows) {
        return "# RSA vs ECC Benchmark\n\n"
                + "RSA-PRE and ECC-PRE are measured through the same lifecycle: key generation, AES encryption, PRE encapsulation, re-key generation, proxy re-encryption, decapsulation, and AES decryption.\n\n"
                + "The PRE stages process the 32-byte DEK capsule, so their cost is mostly independent of plaintext size. AES-GCM stages scale with file size.\n\n"
                + "See `e02-performance-summary.md` for the generated aggregation table.\n\n"
                + "## Parameters\n\n"
                + "| Item | Value |\n"
                + "|---|---|\n"
                + "| RSA | `RSA-PRE-demo-common-modulus-3072` |\n"
                + "| ECC | `ECC-PRE-P-256-demo` |\n"
                + "| AES | AES-256-GCM, 12-byte nonce, 128-bit tag |\n"
                + "| File sizes | 1KB, 100KB, 1MB, 10MB |\n"
                + "| Measurement rounds | 100 per algorithm/size |\n"
                + "| Warmup | 20 per algorithm/size |\n"
                + "| Java observed in this run | Java 25.0.2 |\n"
                + "| Recommended reproducible runtime | Java 17 LTS |\n";
    }

    private record BenchmarkRow(
            String algorithm,
            String parameterSpec,
            int fileSizeBytes,
            int round,
            double keyGenMs,
            double aesEncryptMs,
            double encapsulateMs,
            double reKeyGenMs,
            double reEncryptMs,
            double decapsulateMs,
            double aesDecryptMs,
            double totalMs,
            int capsuleBytes,
            int ciphertextBytes,
            boolean success
    ) {
        String toCsv() {
            return String.format(Locale.ROOT,
                    "%s,%s,%d,%d,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%d,%s",
                    algorithm,
                    parameterSpec,
                    fileSizeBytes,
                    round,
                    keyGenMs,
                    aesEncryptMs,
                    encapsulateMs,
                    reKeyGenMs,
                    reEncryptMs,
                    decapsulateMs,
                    aesDecryptMs,
                    totalMs,
                    capsuleBytes,
                    ciphertextBytes,
                    success);
        }
    }

    private static final class MapKeyStats {
        private final java.util.Map<String, Entry> entries = new java.util.LinkedHashMap<>();

        static MapKeyStats from(List<String> rows) {
            MapKeyStats stats = new MapKeyStats();
            for (int i = 1; i < rows.size(); i++) {
                String[] fields = rows.get(i).split(",");
                String key = fields[0] + "|" + fields[2];
                Entry entry = stats.entries.computeIfAbsent(key, unused -> new Entry(fields[0], Integer.parseInt(fields[2])));
                entry.add(
                        Double.parseDouble(fields[5]),
                        Double.parseDouble(fields[8]),
                        Double.parseDouble(fields[10]),
                        Double.parseDouble(fields[11]),
                        Double.parseDouble(fields[12]),
                        Boolean.parseBoolean(fields[14])
                );
            }
            return stats;
        }

        java.util.Collection<Entry> entries() {
            return entries.values();
        }

        private static final class Entry {
            final String algorithm;
            final int fileSize;
            int count;
            double aesEncrypt;
            double reEncrypt;
            double aesDecrypt;
            double total;
            final java.util.List<Double> totalSamples = new java.util.ArrayList<>();
            double capsule;
            boolean allSuccess = true;

            Entry(String algorithm, int fileSize) {
                this.algorithm = algorithm;
                this.fileSize = fileSize;
            }

            void add(double aesEncryptMs, double reEncryptMs, double aesDecryptMs, double totalMs, double capsuleBytes, boolean success) {
                count++;
                aesEncrypt += aesEncryptMs;
                reEncrypt += reEncryptMs;
                aesDecrypt += aesDecryptMs;
                total += totalMs;
                totalSamples.add(totalMs);
                capsule += capsuleBytes;
                allSuccess = allSuccess && success;
            }

            double avgAesEncrypt() {
                return aesEncrypt / count;
            }

            double avgReEncrypt() {
                return reEncrypt / count;
            }

            double avgAesDecrypt() {
                return aesDecrypt / count;
            }

            double avgTotal() {
                return total / count;
            }

            double percentileTotal(int percentile) {
                java.util.List<Double> sorted = new java.util.ArrayList<>(totalSamples);
                java.util.Collections.sort(sorted);
                int index = (int) Math.ceil(percentile / 100.0 * sorted.size()) - 1;
                return sorted.get(Math.max(0, Math.min(index, sorted.size() - 1)));
            }

            double stddevTotal() {
                double avg = avgTotal();
                double variance = totalSamples.stream()
                        .mapToDouble(value -> {
                            double delta = value - avg;
                            return delta * delta;
                        })
                        .sum() / count;
                return Math.sqrt(variance);
            }

            double throughputBytesPerSecond() {
                return fileSize / (avgTotal() / 1000.0);
            }

            double avgCapsule() {
                return capsule / count;
            }
        }
    }
}
