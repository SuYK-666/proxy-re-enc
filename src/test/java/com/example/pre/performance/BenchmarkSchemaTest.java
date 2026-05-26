package com.example.pre.performance;

import com.example.pre.app.BenchmarkApplication;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BenchmarkSchemaTest {
    @Test
    void benchmarkCsvUsesExpectedSchemaAndAllRowsSucceed() throws Exception {
        Path output = Path.of("target", "benchmark-schema", "e02-algorithm-benchmark.csv");
        Path summary = Path.of("target", "benchmark-schema", "summary");
        System.setProperty("rekeyshare.benchmark.warmup", "0");
        System.setProperty("rekeyshare.benchmark.measurement", "1");
        System.setProperty("rekeyshare.benchmark.rawOutput", output.toString());
        System.setProperty("rekeyshare.benchmark.summaryDirectory", summary.toString());
        try {
            BenchmarkApplication.main(new String[0]);
            List<String> rows = Files.readAllLines(output);
            assertEquals("algorithm,parameterSpec,fileSizeBytes,round,keyGenMs,aesEncryptMs,encapsulateMs,reKeyGenMs,reEncryptMs,decapsulateMs,aesDecryptMs,totalMs,capsuleBytes,ciphertextBytes,success", rows.get(0));
            assertEquals(9, rows.size());
            assertTrue(rows.stream().skip(1).allMatch(row -> row.endsWith(",true")));
            assertTrue(Files.readString(summary.resolve("e02-performance-summary.md")).contains("Capsule Bytes"));
        } finally {
            System.clearProperty("rekeyshare.benchmark.warmup");
            System.clearProperty("rekeyshare.benchmark.measurement");
            System.clearProperty("rekeyshare.benchmark.rawOutput");
            System.clearProperty("rekeyshare.benchmark.summaryDirectory");
        }
    }
}
