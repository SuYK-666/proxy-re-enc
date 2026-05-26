package com.example.pre.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class BenchmarkResultService {
    public String summaryJson(Path csv) {
        try {
            if (!Files.exists(csv)) {
                return "{\"code\":\"SUCCESS\",\"available\":false,\"path\":\"" + json(csv.toString()) + "\"}";
            }
            Map<String, Stats> stats = new LinkedHashMap<>();
            for (String line : Files.readAllLines(csv).stream().skip(1).toList()) {
                if (line.isBlank()) {
                    continue;
                }
                String[] f = line.split(",");
                String key = f[0] + "|" + f[2];
                Stats s = stats.computeIfAbsent(key, unused -> new Stats(f[0], f[1], Integer.parseInt(f[2])));
                s.add(Double.parseDouble(f[8]), Double.parseDouble(f[11]), Integer.parseInt(f[12]), Boolean.parseBoolean(f[14]));
            }
            StringBuilder sb = new StringBuilder();
            sb.append("{\"code\":\"SUCCESS\",\"available\":true,\"path\":\"").append(json(csv.toString())).append("\",\"results\":[");
            int i = 0;
            for (Stats s : stats.values()) {
                if (i++ > 0) {
                    sb.append(',');
                }
                sb.append("{\"algorithm\":\"").append(s.algorithm).append("\",\"parameterSpec\":\"")
                        .append(s.parameterSpec).append("\",\"fileSizeBytes\":").append(s.fileSizeBytes)
                        .append(",\"rounds\":").append(s.count)
                        .append(",\"avgReEncryptMs\":").append(format(s.avgReEncrypt()))
                        .append(",\"avgTotalMs\":").append(format(s.avgTotal()))
                        .append(",\"minTotalMs\":").append(format(s.minTotal()))
                        .append(",\"maxTotalMs\":").append(format(s.maxTotal()))
                        .append(",\"p50TotalMs\":").append(format(s.percentileTotal(50)))
                        .append(",\"p95TotalMs\":").append(format(s.percentileTotal(95)))
                        .append(",\"p99TotalMs\":").append(format(s.percentileTotal(99)))
                        .append(",\"stddevTotalMs\":").append(format(s.stddevTotal()))
                        .append(",\"throughputBytesPerSecond\":").append(format(s.throughputBytesPerSecond()))
                        .append(",\"capsuleBytes\":").append(s.capsuleBytes)
                        .append(",\"allSuccess\":").append(s.allSuccess).append('}');
            }
            sb.append("]}");
            return sb.toString();
        } catch (IOException e) {
            throw new ReKeyShareException(ErrorCode.INVALID_REQUEST, "benchmark summary failed: " + e.getMessage());
        }
    }

    private static String format(double value) {
        return String.format(java.util.Locale.ROOT, "%.4f", value);
    }

    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static final class Stats {
        final String algorithm;
        final String parameterSpec;
        final int fileSizeBytes;
        int count;
        double reEncryptMs;
        double totalMs;
        final List<Double> totalSamples = new ArrayList<>();
        int capsuleBytes;
        boolean allSuccess = true;

        Stats(String algorithm, String parameterSpec, int fileSizeBytes) {
            this.algorithm = algorithm;
            this.parameterSpec = parameterSpec;
            this.fileSizeBytes = fileSizeBytes;
        }

        void add(double reEncryptMs, double totalMs, int capsuleBytes, boolean success) {
            count++;
            this.reEncryptMs += reEncryptMs;
            this.totalMs += totalMs;
            this.totalSamples.add(totalMs);
            this.capsuleBytes = capsuleBytes;
            this.allSuccess = this.allSuccess && success;
        }

        double avgReEncrypt() {
            return reEncryptMs / count;
        }

        double avgTotal() {
            return totalMs / count;
        }

        double minTotal() {
            return totalSamples.stream().mapToDouble(Double::doubleValue).min().orElse(0);
        }

        double maxTotal() {
            return totalSamples.stream().mapToDouble(Double::doubleValue).max().orElse(0);
        }

        double percentileTotal(int percentile) {
            List<Double> sorted = new ArrayList<>(totalSamples);
            Collections.sort(sorted);
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
            return fileSizeBytes / (avgTotal() / 1000.0);
        }
    }
}
