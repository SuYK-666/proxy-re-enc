package com.example.pre.performance;

import com.example.pre.app.BenchmarkApplication;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PreBenchmarkTest {
    @Test
    void benchmarkApplicationWritesCsv() throws Exception {
        Path result = Path.of("target", "pre-benchmark", "e02-algorithm-benchmark.csv");
        System.setProperty("rekeyshare.benchmark.warmup", "0");
        System.setProperty("rekeyshare.benchmark.measurement", "1");
        System.setProperty("rekeyshare.benchmark.rawOutput", result.toString());
        System.setProperty("rekeyshare.benchmark.summaryDirectory", "target/pre-benchmark/summary");
        try {
            BenchmarkApplication.main(new String[0]);
            assertTrue(Files.exists(result));
            String csv = Files.readString(result);
            assertTrue(csv.contains("RSA-PRE"));
            assertTrue(csv.contains("ECC-PRE"));
        } finally {
            System.clearProperty("rekeyshare.benchmark.warmup");
            System.clearProperty("rekeyshare.benchmark.measurement");
            System.clearProperty("rekeyshare.benchmark.rawOutput");
            System.clearProperty("rekeyshare.benchmark.summaryDirectory");
        }
    }
}
