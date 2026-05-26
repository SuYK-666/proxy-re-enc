package com.example.pre.service;

import com.example.pre.model.AlgorithmType;
import com.example.pre.model.RecipientShareSubmission;
import com.example.pre.model.ReKeySession;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public final class EccRecipientShareService {
    private final Map<String, ReKeySession> sessions = new LinkedHashMap<>();
    private final Map<String, RecipientShareSubmission> submissions = new LinkedHashMap<>();
    private final RecipientShareVerifier verifier = new RecipientShareVerifier();

    public ReKeySession createSession(String dataId, String ownerId, String recipientId) {
        ReKeySession session = ReKeySession.create(dataId, ownerId, recipientId, AlgorithmType.ECC_PRE,
                Instant.now().plus(15, ChronoUnit.MINUTES));
        sessions.put(session.sessionId(), session);
        return session;
    }

    public void submitRecipientShare(RecipientShareSubmission submission) {
        ReKeySession session = sessions.get(submission.sessionId());
        if (session == null) {
            throw new ReKeyShareException(ErrorCode.INVALID_REKEY_SESSION, "session not found");
        }
        verifier.verify(session, submission);
        submissions.put(submission.sessionId(), submission);
        sessions.put(submission.sessionId(), session.shareSubmitted());
    }

    public Optional<RecipientShareSubmission> findSubmission(String sessionId) {
        return Optional.ofNullable(submissions.get(sessionId));
    }

    public ReKeySession complete(String sessionId) {
        ReKeySession session = requireSession(sessionId);
        requireVerifiedSubmission(sessionId);
        ReKeySession completed = session.completed();
        sessions.put(sessionId, completed);
        return completed;
    }

    public ReKeySession requireSession(String sessionId) {
        ReKeySession session = sessions.get(sessionId);
        if (session == null) {
            throw new ReKeyShareException(ErrorCode.INVALID_REKEY_SESSION, "session not found");
        }
        return session;
    }

    public ReKeySession requireCompleted(String sessionId) {
        ReKeySession session = requireSession(sessionId);
        if (!"COMPLETED".equals(session.status()) && !"SHARE_SUBMITTED".equals(session.status())) {
            throw new ReKeyShareException(ErrorCode.INVALID_REKEY_SESSION, "recipient share has not been submitted");
        }
        return session;
    }

    public RecipientShareSubmission requireVerifiedSubmission(String sessionId) {
        return findSubmission(sessionId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.INVALID_RECIPIENT_SHARE, "recipient share not submitted"));
    }
}
