package com.example.pre.app;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationCliTest {
    @Test
    void verifiesEnvelopeAuditAndAttackMatrixAsJsonCommands() throws Exception {
        for (String[] command : new String[][]{
                {"crypto", "verify-envelope"},
                {"audit", "verify"},
                {"attack-matrix", "check"}
        }) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            assertEquals(0, VerificationCli.run(command, new PrintStream(output)));
            assertTrue(output.toString(java.nio.charset.StandardCharsets.UTF_8).contains("\"valid\":true"));
        }
    }
}
