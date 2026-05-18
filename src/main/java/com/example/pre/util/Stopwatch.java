package com.example.pre.util;

public final class Stopwatch {
    private final long startedAt;

    private Stopwatch() {
        this.startedAt = System.nanoTime();
    }

    public static Stopwatch start() {
        return new Stopwatch();
    }

    public long elapsedNanos() {
        return System.nanoTime() - startedAt;
    }
}
