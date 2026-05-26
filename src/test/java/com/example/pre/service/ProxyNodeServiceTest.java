package com.example.pre.service;

import com.example.pre.model.AlgorithmType;
import com.example.pre.model.UserRole;
import com.example.pre.storage.InMemoryAuditRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProxyNodeServiceTest {
    @Test
    void enforcesAllowedSchemeAndQuota() {
        ProxyNodeService service = new ProxyNodeService(new InMemoryAuditRepository());
        service.register("admin", "proxy-a", "fp", Set.of("tenant-a"), Set.of(AlgorithmType.RSA_PRE), 1);
        SecurityContext context = context("proxy-a");

        assertDoesNotThrow(() -> service.assertCanProxy(context, AlgorithmType.RSA_PRE));
        assertEquals(ErrorCode.PROXY_QUOTA_EXCEEDED,
                assertThrows(ReKeyShareException.class,
                        () -> service.assertCanProxy(context, AlgorithmType.RSA_PRE)).code());

        service.register("admin", "proxy-b", "fp", Set.of("tenant-a"), Set.of(AlgorithmType.ECC_PRE), 2);
        assertEquals(ErrorCode.SCHEME_NOT_ALLOWED,
                assertThrows(ReKeyShareException.class,
                        () -> service.assertCanProxy(context("proxy-b"), AlgorithmType.RSA_PRE)).code());
    }

    @Test
    void rejectsRevokedProxy() {
        ProxyNodeService service = new ProxyNodeService(new InMemoryAuditRepository());
        service.register("admin", "proxy-a", "fp", Set.of("tenant-a"));
        service.revoke("admin", "proxy-a");
        assertEquals(ErrorCode.PROXY_INACTIVE,
                assertThrows(ReKeyShareException.class,
                        () -> service.assertCanProxy(context("proxy-a"), AlgorithmType.RSA_PRE)).code());
    }

    private static SecurityContext context(String proxyId) {
        return new SecurityContext(proxyId, UserRole.PROXY, "tenant-a", "token",
                Instant.now().minusSeconds(1).getEpochSecond(), Instant.now().plusSeconds(30).getEpochSecond());
    }
}
