package com.example.pre.app;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public final class HealthCheckApplication {
    private HealthCheckApplication() {
    }

    public static void main(String[] args) throws Exception {
        String url = args.length == 0 ? "http://127.0.0.1:8080/" : args[0];
        HttpResponse<Void> result = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        if (result.statusCode() != 200) {
            throw new IllegalStateException("health endpoint status: " + result.statusCode());
        }
    }
}
