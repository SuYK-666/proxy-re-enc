package com.example.pre.storage;

import com.example.pre.crypto.hash.Hash;
import com.example.pre.model.AuditEvent;
import com.example.pre.service.ErrorCode;
import com.example.pre.service.ReKeyShareException;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class JdbcAuditRepository implements AuditRepository {
    private static final String GENESIS_HASH = "GENESIS";
    private final String jdbcUrl;
    private final String username;
    private final String password;

    public JdbcAuditRepository(String jdbcUrl, String username, String password) {
        this.jdbcUrl = jdbcUrl;
        this.username = username;
        this.password = password;
        initialize();
    }

    @Override
    public synchronized void record(AuditEvent event) {
        List<AuditEvent> current = findAll();
        String previousHash = current.isEmpty() ? GENESIS_HASH : current.get(current.size() - 1).eventHash();
        String eventHash = Hash.sha256Hex(event.canonicalWithoutHash(previousHash));
        AuditEvent chained = event.withHash(previousHash, eventHash);
        String sql = """
                insert into audit_events (
                    event_id, timestamp_utc, actor, actor_role, action, target_type, target_id,
                    success, message, request_id, trace_id, source_ip, user_agent, error_code,
                    failure_reason, algorithm, data_id, grant_id, package_id, detail_json,
                    previous_hash, event_hash
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, chained);
            statement.executeUpdate();
        } catch (SQLException e) {
            throw storageError("audit insert failed", e);
        }
    }

    @Override
    public synchronized List<AuditEvent> findAll() {
        String sql = """
                select event_id, timestamp_utc, actor, actor_role, action, target_type, target_id,
                       success, message, request_id, trace_id, source_ip, user_agent, error_code,
                       failure_reason, algorithm, data_id, grant_id, package_id, detail_json,
                       previous_hash, event_hash
                  from audit_events
                 order by sequence asc
                """;
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet rs = statement.executeQuery()) {
            List<AuditEvent> events = new ArrayList<>();
            while (rs.next()) {
                events.add(read(rs));
            }
            return List.copyOf(events);
        } catch (SQLException e) {
            throw storageError("audit query failed", e);
        }
    }

    private void initialize() {
        String sql = """
                create table if not exists audit_events (
                    sequence bigint generated always as identity primary key,
                    event_id varchar(64) not null,
                    timestamp_utc varchar(64) not null,
                    actor varchar(128) not null,
                    actor_role varchar(64) not null,
                    action varchar(128) not null,
                    target_type varchar(128) not null,
                    target_id varchar(256) not null,
                    success boolean not null,
                    message clob not null,
                    request_id varchar(128) not null,
                    trace_id varchar(128) not null,
                    source_ip varchar(128) not null,
                    user_agent varchar(512) not null,
                    error_code varchar(128) not null,
                    failure_reason clob not null,
                    algorithm varchar(64) not null,
                    data_id varchar(128) not null,
                    grant_id varchar(128) not null,
                    package_id varchar(128) not null,
                    detail_json clob not null,
                    previous_hash varchar(128) not null,
                    event_hash varchar(128) not null
                )
                """;
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.executeUpdate();
        } catch (SQLException e) {
            throw storageError("audit schema initialization failed", e);
        }
    }

    private Connection connection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, username, password);
    }

    private static void bind(PreparedStatement statement, AuditEvent event) throws SQLException {
        statement.setString(1, event.eventId());
        statement.setString(2, event.timestamp().toString());
        statement.setString(3, event.actor());
        statement.setString(4, event.actorRole());
        statement.setString(5, event.action());
        statement.setString(6, event.targetType());
        statement.setString(7, event.target());
        statement.setBoolean(8, event.success());
        statement.setString(9, event.message());
        statement.setString(10, event.requestId());
        statement.setString(11, event.traceId());
        statement.setString(12, event.sourceIp());
        statement.setString(13, event.userAgent());
        statement.setString(14, event.errorCode());
        statement.setString(15, event.failureReason());
        statement.setString(16, event.algorithm());
        statement.setString(17, event.dataId());
        statement.setString(18, event.grantId());
        statement.setString(19, event.packageId());
        statement.setString(20, event.detailJson());
        statement.setString(21, event.previousHash());
        statement.setString(22, event.eventHash());
    }

    private static AuditEvent read(ResultSet rs) throws SQLException {
        return new AuditEvent(
                rs.getString("event_id"),
                Instant.parse(rs.getString("timestamp_utc")),
                rs.getString("actor"),
                rs.getString("actor_role"),
                rs.getString("action"),
                rs.getString("target_type"),
                rs.getString("target_id"),
                rs.getBoolean("success"),
                rs.getString("message"),
                rs.getString("request_id"),
                rs.getString("trace_id"),
                rs.getString("source_ip"),
                rs.getString("user_agent"),
                rs.getString("error_code"),
                rs.getString("failure_reason"),
                rs.getString("algorithm"),
                rs.getString("data_id"),
                rs.getString("grant_id"),
                rs.getString("package_id"),
                rs.getString("detail_json"),
                rs.getString("previous_hash"),
                rs.getString("event_hash")
        );
    }

    private static ReKeyShareException storageError(String message, SQLException cause) {
        return new ReKeyShareException(ErrorCode.AUDIT_CHAIN_BROKEN, message + ": " + cause.getMessage());
    }
}
