package com.example.pre.service;

public final class ReKeyShareException extends RuntimeException {
    private final ErrorCode code;

    public ReKeyShareException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }
}
