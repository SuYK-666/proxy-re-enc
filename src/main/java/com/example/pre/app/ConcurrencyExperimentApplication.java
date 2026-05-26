package com.example.pre.app;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

public final class ConcurrencyExperimentApplication {
    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    private ConcurrencyExperimentApplication() {
    }

    public static void main(String[] args) throws Exception {
        Path raw = Path.of("docs", "reports", "raw", "e09-concurrency-results.csv");
        Path summary = Path.of("docs", "reports", "summary", "e09-concurrency-summary.md");
        Files.createDirectories(raw.getParent());
        Files.createDirectories(summary.getParent());
        List<String> rows = new ArrayList<>();
        rows.add("concurrency,maxAccess,success,rejected,overIssued,result");
        boolean allPass = true;
        ReKeyShareApplication.RunningServer server = ReKeyShareApplication.startDemo(0);
        try {
            String base = "http://localhost:" + server.port();
            String alice = createUser(base, "Alice", "OWNER");
            String bob = createUser(base, "Bob", "RECIPIENT");
            String proxy = createUser(base, "proxy", "PROXY");
            for (int limit : new int[]{1, 3, 10}) {
                String data = field(post(base + "/api/data/upload", alice, "plaintext=e09-" + limit).body(), "dataId");
                String grant = field(post(base + "/api/grants", alice, "dataId=" + data
                        + "&recipientId=Bob&maxAccessCount=" + limit + "&maxDownloadCount=" + limit).body(), "grantId");
                String dataPackage = field(post(base + "/api/proxy/re-encrypt", proxy, "grantId=" + grant).body(), "packageId");
                int success = compete(base, dataPackage, bob);
                int overIssued = Math.max(0, success - limit);
                boolean pass = success == limit && overIssued == 0;
                allPass &= pass;
                rows.add("100," + limit + "," + success + "," + (100 - success) + "," + overIssued
                        + "," + (pass ? "PASS" : "FAIL"));
            }
        } finally {
            server.stop();
        }
        Files.write(raw, rows);
        Files.writeString(summary, "# E09 Concurrent Access Limits\n\n"
                + "- Commit: `" + System.getProperty("rekeyshare.commit", "working-tree") + "`\n"
                + "- JDK: `" + System.getProperty("java.version") + "`\n"
                + "- Generated: `" + Instant.now() + "`\n\n"
                + "One hundred concurrent download attempts competed for grants with limits 1, 3 and 10.\n\n"
                + "Raw data: `../raw/e09-concurrency-results.csv`\n\n"
                + "Result: **" + (allPass ? "PASS" : "FAIL") + "** (no over-issuance).\n");
    }

    private static int compete(String base, String packageId, String bob) throws Exception {
        var executor = Executors.newFixedThreadPool(100);
        try {
            List<Future<Integer>> requests = new ArrayList<>();
            for (int index = 0; index < 100; index++) {
                requests.add(executor.submit(() -> get(base + "/api/shared-packages/" + packageId, bob).statusCode()));
            }
            int successes = 0;
            for (Future<Integer> response : requests) {
                if (response.get() == 200) {
                    successes++;
                }
            }
            return successes;
        } finally {
            executor.shutdownNow();
        }
    }

    private static String createUser(String base, String id, String role) throws Exception {
        return field(post(base + "/api/users", "", "userId=" + id + "&role=" + role + "&algorithm=RSA_PRE").body(), "token");
    }

    private static HttpResponse<String> post(String uri, String token, String body) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(uri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (!token.isBlank()) {
            builder.header("Authorization", "Bearer " + token);
        }
        return CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> get(String uri, String token) throws Exception {
        return CLIENT.send(HttpRequest.newBuilder(URI.create(uri)).header("Authorization", "Bearer " + token)
                .GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String field(String json, String name) {
        var matcher = Pattern.compile("\"" + name + "\":\"([^\"]+)\"").matcher(json);
        if (!matcher.find()) {
            throw new IllegalArgumentException("missing " + name + " in " + json);
        }
        return matcher.group(1);
    }
}
