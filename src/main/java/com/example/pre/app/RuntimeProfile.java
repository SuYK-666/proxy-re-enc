package com.example.pre.app;

public enum RuntimeProfile {
    PRODUCTION,
    DEMO;

    public static RuntimeProfile fromProperty() {
        String value = System.getProperty("rekeyshare.profile", System.getenv().getOrDefault("REKEYSHARE_PROFILE", "production"));
        return "demo".equalsIgnoreCase(value) ? DEMO : PRODUCTION;
    }

    public boolean demoFeaturesEnabled() {
        return this == DEMO;
    }
}
