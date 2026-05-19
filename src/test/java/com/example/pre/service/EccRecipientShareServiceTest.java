package com.example.pre.service;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.model.RecipientShareSubmission;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EccRecipientShareServiceTest {
    @Test
    void acceptsRecipientShareGeneratedByDemoClientSimulator() {
        EccPreScheme scheme = new EccPreScheme();
        var bob = new com.example.pre.model.User("Bob", scheme.generateKeyPair("Bob"));
        EccRecipientShareService service = new EccRecipientShareService();
        var session = service.createSession("data-1", "Alice", "Bob");
        var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, session.cryptoContext());
        service.submitRecipientShare(submission(session, "Bob", share));
        assertTrue(service.findSubmission(session.sessionId()).isPresent());
    }

    @Test
    void rejectsRecipientMismatch() {
        EccPreScheme scheme = new EccPreScheme();
        var bob = new com.example.pre.model.User("Bob", scheme.generateKeyPair("Bob"));
        EccRecipientShareService service = new EccRecipientShareService();
        var session = service.createSession("data-1", "Alice", "Bob");
        var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, session.cryptoContext());
        assertThrows(ReKeyShareException.class,
                () -> service.submitRecipientShare(submission(session, "Charlie", share)));
    }

    @Test
    void rejectsWrongChallengeAndSignature() {
        EccPreScheme scheme = new EccPreScheme();
        var bob = new com.example.pre.model.User("Bob", scheme.generateKeyPair("Bob"));
        EccRecipientShareService service = new EccRecipientShareService();
        var session = service.createSession("data-1", "Alice", "Bob");
        var share = DemoPrivateKeyStore.createEccRecipientShareLocally(bob, session.cryptoContext());
        assertThrows(ReKeyShareException.class,
                () -> service.submitRecipientShare(new RecipientShareSubmission(
                        session.sessionId(),
                        session.dataId(),
                        session.ownerId(),
                        "Bob",
                        "wrong-challenge",
                        share,
                        DemoRecipientShareSignature.shareHash(share),
                        DemoRecipientShareSignature.sign(session, share),
                        Instant.now())));
        assertThrows(ReKeyShareException.class,
                () -> service.submitRecipientShare(new RecipientShareSubmission(
                        session.sessionId(),
                        session.dataId(),
                        session.ownerId(),
                        "Bob",
                        session.challenge(),
                        share,
                        DemoRecipientShareSignature.shareHash(share),
                        "bad-signature",
                        Instant.now())));
    }

    private static RecipientShareSubmission submission(
            com.example.pre.model.ReKeySession session,
            String recipientId,
            com.example.pre.crypto.ecc.RecipientReKeyShare share
    ) {
        return new RecipientShareSubmission(
                session.sessionId(),
                session.dataId(),
                session.ownerId(),
                recipientId,
                session.challenge(),
                share,
                DemoRecipientShareSignature.shareHash(share),
                DemoRecipientShareSignature.sign(session, share),
                Instant.now()
        );
    }
}
