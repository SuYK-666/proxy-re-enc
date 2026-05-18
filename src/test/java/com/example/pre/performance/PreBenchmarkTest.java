package com.example.pre.performance;

import com.example.pre.app.BenchmarkApplication;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PreBenchmarkTest {
    @Test
    void benchmarkApplicationWritesCsv() throws Exception {
        BenchmarkApplication.main(new String[0]);
        Path result = Path.of("docs/reports/performance-results.csv");
        assertTrue(Files.exists(result));
        String csv = Files.readString(result);
        assertTrue(csv.contains("RSA-PRE"));
        assertTrue(csv.contains("ECC-PRE"));
    }
}
