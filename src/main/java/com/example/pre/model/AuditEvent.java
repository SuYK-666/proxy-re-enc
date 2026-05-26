package com.example.pre.model;

import java.time.Instant;
import java.util.UUID;

public record AuditEvent(
        String eventId,
        Instant timestamp,
        String actor,
        String actorRole,
        String action,
        String targetType,
        String target,
        boolean success,
        String message,
        String requestId,
        String traceId,
        String sourceIp,
        String userAgent,
        String errorCode,
        String failureReason,
        String algorithm,
        String dataId,
        String grantId,
        String packageId,
        String detailJson,
        String previousHash,
        String eventHash
) {
    public AuditEvent(Instant timestamp, String actor, String action, String target, boolean success, String message) {
        this(UUID.randomUUID().toString(), timestamp, actor, "", action, "", target, success, message, "", "",
                "", "", success ? "" : message, "", "", "", "", "", "{}", "", "");
    }

    public AuditEvent withHash(String previousHash, String eventHash) {
        return new AuditEvent(
                eventId,
                timestamp,
                actor,
                actorRole,
                action,
                targetType,
                target,
                success,
                message,
                requestId,
                traceId,
                sourceIp,
                userAgent,
                errorCode,
                failureReason,
                algorithm,
                dataId,
                grantId,
                packageId,
                detailJson,
                previousHash,
                eventHash
        );
    }

    public AuditEvent withAction(String newAction) {
        return new AuditEvent(
                eventId,
                timestamp,
                actor,
                actorRole,
                newAction,
                targetType,
                target,
                success,
                message,
                requestId,
                traceId,
                sourceIp,
                userAgent,
                errorCode,
                failureReason,
                algorithm,
                dataId,
                grantId,
                packageId,
                detailJson,
                previousHash,
                eventHash
        );
    }

    public String canonicalWithoutHash(String previousHashValue) {
        return "eventId=" + eventId
                + "|timestamp=" + timestamp
                + "|actor=" + actor
                + "|actorRole=" + actorRole
                + "|action=" + action
                + "|targetType=" + targetType
                + "|target=" + target
                + "|success=" + success
                + "|message=" + message
                + "|requestId=" + requestId
                + "|traceId=" + traceId
                + "|sourceIp=" + sourceIp
                + "|userAgent=" + userAgent
                + "|errorCode=" + errorCode
                + "|failureReason=" + failureReason
                + "|algorithm=" + algorithm
                + "|dataId=" + dataId
                + "|grantId=" + grantId
                + "|packageId=" + packageId
                + "|detailJson=" + detailJson
                + "|previousHash=" + previousHashValue;
    }
}
