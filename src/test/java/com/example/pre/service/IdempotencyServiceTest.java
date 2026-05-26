package com.example.pre.service;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IdempotencyServiceTest {
    @Test
    void replayReturnsOriginalResultWithoutExecutingMutationAgain() {
        IdempotencyService service = new IdempotencyService(Duration.ofMinutes(5));
        AtomicInteger mutations = new AtomicInteger();

        String first = service.execute("request-1", "alice", "CREATE_GRANT", "data-1", "{\"recipient\":\"bob\"}",
                () -> "grant-" + mutations.incrementAndGet());
        String replay = service.execute("request-1", "alice", "CREATE_GRANT", "data-1", "{\"recipient\":\"bob\"}",
                () -> "grant-" + mutations.incrementAndGet());

        assertEquals(first, replay);
        assertEquals(1, mutations.get());
    }

    @Test
    void reusedKeyWithDifferentRequestFailsWithStableCode() {
        IdempotencyService service = new IdempotencyService(Duration.ofMinutes(5));
        service.execute("request-1", "alice", "CREATE_GRANT", "data-1", "body-a", () -> "grant-1");

        ReKeyShareException failure = assertThrows(ReKeyShareException.class,
                () -> service.execute("request-1", "alice", "CREATE_GRANT", "data-1", "body-b", () -> "grant-2"));
        assertEquals(ErrorCode.IDEMPOTENCY_CONFLICT, failure.code());
    }
}
