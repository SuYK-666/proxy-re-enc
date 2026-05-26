package com.example.pre.storage;

import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.PackageStatus;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Durable governance metadata store. Ciphertext content remains in object storage; this
 * adapter persists authorization and package state needed for recovery and atomic limits.
 */
public final class JdbcGovernanceRepository {
    public record RecoverySnapshot(int dataObjects, int grants, int packages, int accessCount, String packageStatus) {
    }

    private final String jdbcUrl;
    private final String username;
    private final String password;

    public JdbcGovernanceRepository(String jdbcUrl, String username, String password) {
        this.jdbcUrl = jdbcUrl;
        this.username = username;
        this.password = password;
        try (Connection connection = connection()) {
            JdbcSchemaInitializer.initialize(connection);
        } catch (SQLException e) {
            throw storageError("governance schema initialization failed", e);
        }
    }

    public void saveWorkflow(
            String tenantId,
            User owner,
            User recipient,
            EncryptedDataPackage data,
            ShareGrant grant,
            ReEncryptedPackage dataPackage
    ) {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try {
                saveUser(connection, tenantId, owner);
                saveUser(connection, tenantId, recipient);
                saveData(connection, tenantId, data);
                saveGrant(connection, tenantId, grant);
                savePackage(connection, tenantId, dataPackage);
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw storageError("workflow persistence failed", e);
        }
    }

    public boolean consumeGrantAccess(String tenantId, String grantId) {
        String sql = """
                update grants
                   set access_count = access_count + 1, version = version + 1
                 where tenant_id = ? and grant_id = ? and status = 'ACTIVE'
                   and access_count < max_access_count
                """;
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId);
            statement.setString(2, grantId);
            return statement.executeUpdate() == 1;
        } catch (SQLException e) {
            throw storageError("atomic access consumption failed", e);
        }
    }

    public void revokeAndInvalidate(String tenantId, String grantId) {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement revoke = connection.prepareStatement(
                    "update grants set status = 'REVOKED', version = version + 1 where tenant_id = ? and grant_id = ?");
                 PreparedStatement invalidate = connection.prepareStatement(
                         "update packages set status = 'INVALIDATED' where tenant_id = ? and grant_id = ? and status = 'ACTIVE'")) {
                revoke.setString(1, tenantId);
                revoke.setString(2, grantId);
                revoke.executeUpdate();
                invalidate.setString(1, tenantId);
                invalidate.setString(2, grantId);
                invalidate.executeUpdate();
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw storageError("revoke transaction failed", e);
        }
    }

    public RecoverySnapshot snapshot(String tenantId, String grantId, String packageId) {
        String counts = """
                select
                  (select count(*) from data_objects where tenant_id = ?) as data_count,
                  (select count(*) from grants where tenant_id = ?) as grant_count,
                  (select count(*) from packages where tenant_id = ?) as package_count,
                  (select access_count from grants where tenant_id = ? and grant_id = ?) as access_count,
                  (select status from packages where tenant_id = ? and package_id = ?) as package_status
                """;
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(counts)) {
            statement.setString(1, tenantId);
            statement.setString(2, tenantId);
            statement.setString(3, tenantId);
            statement.setString(4, tenantId);
            statement.setString(5, grantId);
            statement.setString(6, tenantId);
            statement.setString(7, packageId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("governance recovery query returned no row");
                }
                return new RecoverySnapshot(result.getInt("data_count"), result.getInt("grant_count"),
                        result.getInt("package_count"), result.getInt("access_count"),
                        result.getString("package_status"));
            }
        } catch (SQLException e) {
            throw storageError("governance recovery query failed", e);
        }
    }

    public int dataKeyVersion(String tenantId, String dataId) {
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(
                     "select content_key_version from data_objects where tenant_id = ? and data_id = ?")) {
            statement.setString(1, tenantId);
            statement.setString(2, dataId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("missing persisted data object: " + dataId);
                }
                return result.getInt(1);
            }
        } catch (SQLException e) {
            throw storageError("data key version query failed", e);
        }
    }

    private void saveUser(Connection connection, String tenantId, User user) throws SQLException {
        String sql = "merge into users (tenant_id, user_id, role, status, created_at) key (tenant_id, user_id) values (?, ?, ?, ?, ?)";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId);
            statement.setString(2, user.userId());
            statement.setString(3, user.role().name());
            statement.setString(4, user.status().name());
            statement.setTimestamp(5, java.sql.Timestamp.from(user.createdAt()));
            statement.executeUpdate();
        }
    }

    private void saveData(Connection connection, String tenantId, EncryptedDataPackage data) throws SQLException {
        String sql = """
                merge into data_objects (
                  tenant_id, data_id, owner_id, algorithm, status, content_key_version,
                  ciphertext_hash, storage_path, version, created_at
                ) key (tenant_id, data_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId);
            statement.setString(2, data.dataId());
            statement.setString(3, data.ownerId());
            statement.setString(4, data.algorithm().name());
            statement.setString(5, "ACTIVE");
            statement.setInt(6, data.contentKeyVersion());
            statement.setString(7, data.ciphertextHash());
            statement.setString(8, data.storagePath());
            statement.setLong(9, 0);
            statement.setTimestamp(10, java.sql.Timestamp.from(data.createdAt()));
            statement.executeUpdate();
        }
    }

    private void saveGrant(Connection connection, String tenantId, ShareGrant grant) throws SQLException {
        String sql = """
                merge into grants (
                  tenant_id, grant_id, data_id, owner_id, recipient_id, status, policy_hash,
                  content_key_version, max_access_count, access_count, reencrypt_count,
                  download_count, decrypt_count, version
                ) key (tenant_id, grant_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId);
            statement.setString(2, grant.grantId());
            statement.setString(3, grant.dataId());
            statement.setString(4, grant.ownerId());
            statement.setString(5, grant.recipientId());
            statement.setString(6, grant.status().name());
            statement.setString(7, grant.policyHash());
            statement.setInt(8, grant.contentKeyVersion());
            statement.setInt(9, grant.policy().maxAccessCount());
            statement.setInt(10, grant.accessCount());
            statement.setInt(11, grant.reEncryptCount());
            statement.setInt(12, grant.downloadCount());
            statement.setInt(13, grant.decryptCount());
            statement.setLong(14, 0);
            statement.executeUpdate();
        }
    }

    private void savePackage(Connection connection, String tenantId, ReEncryptedPackage dataPackage) throws SQLException {
        String sql = """
                merge into packages (
                  tenant_id, package_id, grant_id, data_id, recipient_id, status,
                  content_key_version, created_at
                ) key (tenant_id, package_id) values (?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId);
            statement.setString(2, dataPackage.packageId());
            statement.setString(3, dataPackage.grantId());
            statement.setString(4, dataPackage.dataId());
            statement.setString(5, dataPackage.recipientId());
            statement.setString(6, PackageStatus.ACTIVE.name());
            statement.setInt(7, dataPackage.contentKeyVersion());
            statement.setTimestamp(8, java.sql.Timestamp.from(dataPackage.authorizedAt()));
            statement.executeUpdate();
        }
    }

    private Connection connection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, username, password);
    }

    private static IllegalStateException storageError(String message, SQLException cause) {
        return new IllegalStateException(message, cause);
    }
}
