package com.example.pre.crypto.ecc;

import java.math.BigInteger;
import java.time.Instant;

public record RecipientReKeyShare(
        BigInteger maskedScalarShare,
        String sessionId,
        String challengeHash,
        Instant expiresAt
) {
    public RecipientReKeyShare(BigInteger maskedScalarShare) {
        this(maskedScalarShare, "", "", Instant.now().plusSeconds(300));
    }
}
