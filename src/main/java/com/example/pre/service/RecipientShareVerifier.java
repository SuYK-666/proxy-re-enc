package com.example.pre.service;

import com.example.pre.model.RecipientShareSubmission;
import com.example.pre.model.ReKeySession;

public final class RecipientShareVerifier {
    public void verify(ReKeySession session, RecipientShareSubmission submission) {
        if (!session.sessionId().equals(submission.sessionId())) {
            throw new ReKeyShareException(ErrorCode.INVALID_REKEY_SESSION, "session id mismatch");
        }
        if (!session.recipientId().equals(submission.recipientId())) {
            throw new ReKeyShareException(ErrorCode.INVALID_RECIPIENT_SHARE, "recipient mismatch");
        }
        if (!blankOrEquals(submission.dataId(), session.dataId())
                || !blankOrEquals(submission.ownerId(), session.ownerId())
                || !blankOrEquals(submission.challenge(), session.challenge())) {
            throw new ReKeyShareException(ErrorCode.INVALID_REKEY_SESSION, "recipient share is not bound to the session challenge");
        }
        if (session.expired(java.time.Instant.now())) {
            throw new ReKeyShareException(ErrorCode.INVALID_REKEY_SESSION, "session expired");
        }
        if (submission.recipientShare() == null) {
            throw new ReKeyShareException(ErrorCode.INVALID_RECIPIENT_SHARE, "empty recipient share");
        }
        String expectedShareHash = DemoRecipientShareSignature.shareHash(submission.recipientShare());
        if (!blankOrEquals(submission.recipientShareHash(), expectedShareHash)) {
            throw new ReKeyShareException(ErrorCode.INVALID_RECIPIENT_SHARE, "recipient share hash mismatch");
        }
        String expectedSignature = DemoRecipientShareSignature.sign(session, submission.recipientShare());
        if (submission.signature() == null || !expectedSignature.equals(submission.signature())) {
            throw new ReKeyShareException(ErrorCode.INVALID_RECIPIENT_SHARE, "invalid recipient share signature");
        }
    }

    private boolean blankOrEquals(String value, String expected) {
        return value == null || value.isBlank() || value.equals(expected);
    }
}
