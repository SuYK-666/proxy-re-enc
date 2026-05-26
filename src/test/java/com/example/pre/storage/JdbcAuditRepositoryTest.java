package com.example.pre.storage;

import com.example.pre.model.AuditEvent;
import com.example.pre.service.AuditService;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JdbcAuditRepositoryTest {
    @Test
    void auditChainSurvivesRepositoryRestart() throws Exception {
        Path database = Path.of("target", "jdbc-test", "audit-" + java.util.UUID.randomUUID());
        Files.createDirectories(database.getParent());
        String url = "jdbc:h2:file:" + database.toAbsolutePath() + ";DB_CLOSE_DELAY=0";
        try (var connection = DriverManager.getConnection(url, "sa", "")) {
            JdbcSchemaInitializer.initialize(connection);
        }
        JdbcAuditRepository first = new JdbcAuditRepository(url, "sa", "");
        first.record(new AuditEvent(Instant.now(), "alice", "UPLOAD", "data-1", true, "ciphertext"));
        first.record(new AuditEvent(Instant.now(), "proxy", "REENCRYPT", "pkg-1", true, "capsule"));

        JdbcAuditRepository restarted = new JdbcAuditRepository(url, "sa", "");
        assertEquals(2, restarted.findAll().size());
        assertTrue(AuditService.verifyChain(restarted.findAll()).valid());
    }
}
