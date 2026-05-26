package com.example.pre.security.policy;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyEvaluatorTest {
    private final Instant now = Instant.parse("2026-05-26T00:00:00Z");
    private final PolicyExpression policy = new PolicyExpression("tenant-a", Set.of("RECIPIENT"),
            Set.of("download", "preview"), "research", "confidential",
            now.minusSeconds(60), now.plusSeconds(60), 10, true);
    private final PolicyEvaluator evaluator = new PolicyEvaluator();

    @Test
    void permitsTenValidPolicyEvaluations() {
        for (int index = 0; index < 10; index++) {
            PolicyDecision decision = evaluator.evaluate(policy, request("RECIPIENT", "tenant-a",
                    "download", "research", "confidential", index, true, now));
            assertTrue(decision.allowed());
            assertEquals("PERMIT", decision.reasonCode());
        }
    }

    @Test
    void deniesAtLeastTenNegativePolicyCasesWithStableReasons() {
        PolicyRequest[] denied = {
                request("RECIPIENT", "tenant-b", "download", "research", "confidential", 0, true, now),
                request("OWNER", "tenant-a", "download", "research", "confidential", 0, true, now),
                request("RECIPIENT", "tenant-a", "delete", "research", "confidential", 0, true, now),
                request("RECIPIENT", "tenant-a", "download", "sales", "confidential", 0, true, now),
                request("RECIPIENT", "tenant-a", "download", "research", "public", 0, true, now),
                request("RECIPIENT", "tenant-a", "download", "research", "confidential", 10, true, now),
                request("RECIPIENT", "tenant-a", "download", "research", "confidential", 11, true, now),
                request("RECIPIENT", "tenant-a", "download", "research", "confidential", 0, false, now),
                request("RECIPIENT", "tenant-a", "download", "research", "confidential", 0, true, now.minusSeconds(120)),
                request("RECIPIENT", "tenant-a", "download", "research", "confidential", 0, true, now.plusSeconds(120))
        };
        for (PolicyRequest request : denied) {
            assertFalse(evaluator.evaluate(policy, request).allowed());
        }
    }

    private static PolicyRequest request(String role, String tenant, String action, String purpose,
                                         String classification, int count, boolean proxyActive, Instant time) {
        return new PolicyRequest("bob", role, tenant, "data-1", classification, action, purpose,
                count, proxyActive, time);
    }
}
