package com.example.pre.model;

import com.example.pre.crypto.ecc.RecipientReKeyShare;

import java.time.Instant;

public record RecipientShareSubmission(
        String sessionId,
        String dataId,
        String ownerId,
        String recipientId,
        String challenge,
        RecipientReKeyShare recipientShare,
        String recipientShareHash,
        String signature,
        Instant submittedAt
) {
    public RecipientShareSubmission(
            String sessionId,
            String recipientId,
            RecipientReKeyShare recipientShare,
            String signature,
            Instant submittedAt
    ) {
        this(sessionId, "", "", recipientId, "", recipientShare, "", signature, submittedAt);
    }
}
