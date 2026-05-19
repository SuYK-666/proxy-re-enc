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
        BenchmarkApplication.main(new String[0]);
        List<String> rows = Files.readAllLines(Path.of("docs/reports/performance-results.csv"));
        assertEquals("algorithm,parameterSpec,fileSizeBytes,round,keyGenMs,aesEncryptMs,encapsulateMs,reKeyGenMs,reEncryptMs,decapsulateMs,aesDecryptMs,totalMs,capsuleBytes,ciphertextBytes,success", rows.get(0));
        assertTrue(rows.size() >= 25);
        assertTrue(rows.stream().skip(1).allMatch(row -> row.endsWith(",true")));
        assertTrue(Files.readString(Path.of("docs/reports/performance-summary.md")).contains("Capsule Bytes"));
    }
}
