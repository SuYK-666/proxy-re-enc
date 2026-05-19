package com.example.pre.storage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public final class JdbcSchemaInitializer {
    private JdbcSchemaInitializer() {
    }

    public static void initialize(Connection connection) {
        try (Statement statement = connection.createStatement()) {
            for (String sql : schema().split(";")) {
                String trimmed = sql.trim();
                if (!trimmed.isEmpty()) {
                    statement.execute(trimmed);
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("database schema initialization failed", e);
        }
    }

    private static String schema() {
        try (var in = JdbcSchemaInitializer.class.getResourceAsStream("/db/schema.sql")) {
            if (in == null) {
                throw new IllegalStateException("missing /db/schema.sql");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("failed to read schema", e);
        }
    }
}
