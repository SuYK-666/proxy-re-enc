package com.example.pre.service;

import com.example.pre.model.User;
import com.example.pre.model.UserRole;
import com.example.pre.model.UserStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DemoTokenServiceTest {
    @Test
    void verifiesRotatedKeyTokensAndRejectsRevokedOrMalformedTokens() {
        DemoTokenService tokens = new DemoTokenService("first-secret", 60);
        User user = new User("alice", null, "alice", UserRole.OWNER, UserStatus.ACTIVE, Instant.now());
        String original = tokens.issue(user);
        assertEquals("alice", tokens.verify(original).userId());

        tokens.rotateSigningKey("demo-kid-2", "second-secret");
        String rotated = tokens.issue(user);
        var actor = tokens.verify(rotated);
        assertEquals(UserRole.OWNER, actor.role());
        tokens.revoke(actor.tokenId());
        assertEquals(ErrorCode.UNAUTHENTICATED,
                assertThrows(ReKeyShareException.class, () -> tokens.verify(rotated)).code());

        assertEquals(ErrorCode.UNAUTHENTICATED,
                assertThrows(ReKeyShareException.class, () -> tokens.verify("")).code());
        assertEquals(ErrorCode.UNAUTHENTICATED,
                assertThrows(ReKeyShareException.class, () -> tokens.verify("bad-token")).code());
        assertEquals(ErrorCode.UNAUTHENTICATED,
                assertThrows(ReKeyShareException.class, () -> tokens.verify("@@@.invalid")).code());
        assertEquals(ErrorCode.UNAUTHENTICATED,
                assertThrows(ReKeyShareException.class, () -> tokens.verify(original + "changed")).code());
    }

    @Test
    void rejectsExpiredToken() {
        DemoTokenService tokens = new DemoTokenService("expired-secret", -1);
        User user = new User("bob", null, "bob", UserRole.RECIPIENT, UserStatus.ACTIVE, Instant.now());
        assertEquals(ErrorCode.UNAUTHENTICATED,
                assertThrows(ReKeyShareException.class, () -> tokens.verify(tokens.issue(user))).code());
    }
}
