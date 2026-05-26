package com.example.pre.performance;

import com.example.pre.service.BenchmarkResultService;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class BenchmarkResultServiceTest {
    @Test
    void parsesBenchmarkCsvIntoStructuredSummary() throws Exception {
        Path csv = Path.of("target", "benchmark-test", "performance-results.csv");
        Files.createDirectories(csv.getParent());
        Files.writeString(csv, ""
                + "algorithm,parameterSpec,fileSizeBytes,round,keyGenMs,aesEncryptMs,encapsulateMs,reKeyGenMs,reEncryptMs,decapsulateMs,aesDecryptMs,totalMs,capsuleBytes,ciphertextBytes,success\n"
                + "RSA-PRE,common-modulus-3072-demo,1024,1,1,1,1,1,2,1,1,10,444,1052,true\n"
                + "RSA-PRE,common-modulus-3072-demo,1024,2,1,1,1,1,4,1,1,20,444,1052,true\n");

        String json = new BenchmarkResultService().summaryJson(csv);
        assertTrue(json.contains("\"avgReEncryptMs\":3.0000"));
        assertTrue(json.contains("\"avgTotalMs\":15.0000"));
        assertTrue(json.contains("\"p95TotalMs\":20.0000"));
        assertTrue(json.contains("\"stddevTotalMs\":5.0000"));
        assertTrue(json.contains("\"throughputBytesPerSecond\":68266.6667"));
        assertTrue(json.contains("\"allSuccess\":true"));
    }
}
