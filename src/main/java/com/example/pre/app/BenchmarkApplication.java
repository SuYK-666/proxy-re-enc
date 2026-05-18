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
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.SecureRandomUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;

public final class BenchmarkApplication {
    private BenchmarkApplication() {
    }

    public static void main(String[] args) throws Exception {
        Files.createDirectories(Path.of("docs/reports"));
        List<String> lines = new ArrayList<>();
        lines.add("algorithm,stage,avg_ms,p50_ms,p95_ms,min_ms,max_ms,size_bytes");
        benchmark(new RsaPreScheme(RsaCommonModulusParameters.generate(2048)), lines);
        benchmark(new EccPreScheme(), lines);
        Files.write(Path.of("docs/reports/performance-results.csv"), lines);
        lines.forEach(System.out::println);
    }

    private static void benchmark(PreScheme scheme, List<String> lines) {
        int warmup = 3;
        int measurement = 10;
        byte[] dataKey = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        UserKeyPair owner = scheme.generateKeyPair("owner");
        UserKeyPair recipient = scheme.generateKeyPair("recipient");
        EncryptedKeyCapsule capsule = scheme.encapsulate(dataKey, owner.publicKey());
        ReEncryptionKey reKey = createReKey(scheme, owner, recipient);
        EncryptedKeyCapsule transformed = scheme.reEncrypt(capsule, reKey);

        record(lines, scheme.name(), "keygen", warmup, measurement, () -> scheme.generateKeyPair("bench"), 0);
        record(lines, scheme.name(), "encapsulate", warmup, measurement,
                () -> scheme.encapsulate(dataKey, owner.publicKey()), capsule.header().length + capsule.wrappedKey().length);
        record(lines, scheme.name(), "rekey", warmup, measurement,
                () -> createReKey(scheme, owner, recipient), 0);
        record(lines, scheme.name(), "reencrypt", warmup, measurement,
                () -> scheme.reEncrypt(capsule, reKey), transformed.header().length + transformed.wrappedKey().length);
        record(lines, scheme.name(), "decapsulate", warmup, measurement,
                () -> scheme.decapsulate(transformed, recipient.privateKey()), dataKey.length);
    }

    private static ReEncryptionKey createReKey(PreScheme scheme, UserKeyPair owner, UserKeyPair recipient) {
        if (scheme instanceof RsaPreScheme) {
            return new RsaReKeyGenerator().generateReEncryptionKey(
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

    private static void record(
            List<String> lines,
            String algorithm,
            String stage,
            int warmup,
            int measurement,
            Supplier<?> action,
            int sizeBytes
    ) {
        for (int i = 0; i < warmup; i++) {
            action.get();
        }
        List<Double> values = new ArrayList<>();
        for (int i = 0; i < measurement; i++) {
            long start = System.nanoTime();
            action.get();
            values.add((System.nanoTime() - start) / 1_000_000.0);
        }
        Collections.sort(values);
        double avg = values.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        lines.add(String.format(Locale.ROOT, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.4f,%d",
                algorithm,
                stage,
                avg,
                percentile(values, 0.50),
                percentile(values, 0.95),
                values.get(0),
                values.get(values.size() - 1),
                sizeBytes));
    }

    private static double percentile(List<Double> sorted, double p) {
        int index = Math.min(sorted.size() - 1, (int) Math.ceil(p * sorted.size()) - 1);
        return sorted.get(index);
    }
}
