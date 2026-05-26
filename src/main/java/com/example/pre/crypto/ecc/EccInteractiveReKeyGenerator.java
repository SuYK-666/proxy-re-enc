package com.example.pre.crypto.ecc;

import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.util.Bytes;

import java.math.BigInteger;
import java.time.Instant;

public final class EccInteractiveReKeyGenerator {
    public RecipientReKeyShare createRecipientShare(
            EccPrivateKeyMaterial recipientPrivateKey,
            ReKeySessionContext context
    ) {
        if (context == null) {
            throw new IllegalArgumentException("session context is required");
        }
        BigInteger blind = contextBlind(context);
        BigInteger maskedShare = recipientPrivateKey.scalar().modInverse(P256Curve.N)
                .multiply(blind)
                .mod(P256Curve.N);
        return new RecipientReKeyShare(
                maskedShare,
                context.sessionId(),
                challengeHash(context),
                context.createdAt().plusSeconds(900)
        );
    }

    public ReEncryptionKey generateReEncryptionKey(
            EccPrivateKeyMaterial ownerPrivateKey,
            EccPublicKeyMaterial recipientPublicKey,
            RecipientReKeyShare recipientShare,
            ReKeySessionContext context
    ) {
        if (recipientPublicKey == null || context == null) {
            throw new IllegalArgumentException("recipient public key and session context are required");
        }
        validateShare(recipientShare, context);
        BigInteger inverseBlind = contextBlind(context).modInverse(P256Curve.N);
        BigInteger unmaskedShare = recipientShare.maskedScalarShare().multiply(inverseBlind).mod(P256Curve.N);
        return new EccReEncryptionKey(
                ownerPrivateKey.scalar()
                        .multiply(unmaskedShare)
                        .mod(P256Curve.N)
        );
    }

    private static void validateShare(RecipientReKeyShare share, ReKeySessionContext context) {
        if (share.expiresAt() != null && !share.expiresAt().isAfter(Instant.now())) {
            throw new IllegalArgumentException("recipient share expired");
        }
        if (!share.sessionId().isBlank() && !share.sessionId().equals(context.sessionId())) {
            throw new IllegalArgumentException("recipient share session mismatch");
        }
        if (!share.challengeHash().isBlank() && !share.challengeHash().equals(challengeHash(context))) {
            throw new IllegalArgumentException("recipient share challenge mismatch");
        }
    }

    private static BigInteger contextBlind(ReKeySessionContext context) {
        BigInteger blind = Bytes.positiveBigInteger(Hash.sha256(
                ("ReKeyShare-ECC-RecipientShare-v1|" + context.sessionId() + "|" + context.createdAt()).getBytes(java.nio.charset.StandardCharsets.UTF_8)
        )).mod(P256Curve.N);
        return BigInteger.ZERO.equals(blind) ? BigInteger.ONE : blind;
    }

    private static String challengeHash(ReKeySessionContext context) {
        return Hash.sha256Hex(("challenge|" + context.sessionId() + "|" + context.createdAt()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
