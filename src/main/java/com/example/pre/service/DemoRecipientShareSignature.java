package com.example.pre.service;

import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.model.ReKeySession;

import java.nio.charset.StandardCharsets;

public final class DemoRecipientShareSignature {
    private DemoRecipientShareSignature() {
    }

    public static String shareHash(RecipientReKeyShare share) {
        if (share == null || share.maskedScalarShare() == null) {
            return "";
        }
        return Hash.sha256Hex((share.sessionId() + "|" + share.challengeHash() + "|"
                + share.expiresAt() + "|" + share.maskedScalarShare()).getBytes(StandardCharsets.UTF_8));
    }

    public static String message(ReKeySession session, String shareHash) {
        return session.sessionId()
                + "|" + session.challenge()
                + "|" + session.dataId()
                + "|" + session.ownerId()
                + "|" + session.recipientId()
                + "|" + shareHash
                + "|" + session.expiresAt();
    }

    public static String sign(ReKeySession session, RecipientReKeyShare share) {
        String shareHash = shareHash(share);
        return "demo:" + Hash.sha256Hex(message(session, shareHash).getBytes(StandardCharsets.UTF_8));
    }
}
