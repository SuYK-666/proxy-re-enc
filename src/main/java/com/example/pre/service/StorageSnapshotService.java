package com.example.pre.service;

import com.example.pre.model.AuditEvent;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.storage.AuditRepository;
import com.example.pre.storage.DataRepository;
import com.example.pre.storage.GrantRepository;
import com.example.pre.storage.ReEncryptedPackageRepository;
import com.example.pre.storage.UserRepository;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

public final class StorageSnapshotService {
    private final UserRepository users;
    private final DataRepository data;
    private final GrantRepository grants;
    private final ReEncryptedPackageRepository packages;
    private final AuditRepository audit;

    public StorageSnapshotService(
            UserRepository users,
            DataRepository data,
            GrantRepository grants,
            ReEncryptedPackageRepository packages,
            AuditRepository audit
    ) {
        this.users = users;
        this.data = data;
        this.grants = grants;
        this.packages = packages;
        this.audit = audit;
    }

    public Path exportSnapshot(Path output) {
        try {
            if (output.getParent() != null) {
                Files.createDirectories(output.getParent());
            }
            Files.writeString(output, snapshotJson());
            return output;
        } catch (IOException e) {
            throw new ReKeyShareException(ErrorCode.AUDIT_CHAIN_BROKEN, "snapshot export failed: " + e.getMessage());
        }
    }

    public String exportSnapshotHash(Path output) {
        exportSnapshot(output);
        return fileHash(output);
    }

    public Path exportRepositoryFiles(Path directory) {
        try {
            Files.createDirectories(directory);
            writePart(directory.resolve("users.json"), usersJson());
            writePart(directory.resolve("data-objects.json"), dataJson());
            writePart(directory.resolve("grants.json"), grantsJson());
            writePart(directory.resolve("packages.json"), packagesJson());
            writePart(directory.resolve("audit-events.json"), auditJson());
            String manifest = "{"
                    + "\"exportedAt\":\"" + Instant.now() + "\","
                    + "\"usersHash\":\"" + fileHash(directory.resolve("users.json")) + "\","
                    + "\"dataObjectsHash\":\"" + fileHash(directory.resolve("data-objects.json")) + "\","
                    + "\"grantsHash\":\"" + fileHash(directory.resolve("grants.json")) + "\","
                    + "\"packagesHash\":\"" + fileHash(directory.resolve("packages.json")) + "\","
                    + "\"auditEventsHash\":\"" + fileHash(directory.resolve("audit-events.json")) + "\""
                    + "}";
            writePart(directory.resolve("manifest.json"), manifest);
            return directory.resolve("manifest.json");
        } catch (IOException e) {
            throw new ReKeyShareException(ErrorCode.AUDIT_CHAIN_BROKEN, "repository export failed: " + e.getMessage());
        }
    }

    public String fileHash(Path input) {
        try {
            return Hash.sha256Hex(Files.readAllBytes(input));
        } catch (IOException e) {
            throw new ReKeyShareException(ErrorCode.AUDIT_CHAIN_BROKEN, "snapshot hash failed: " + e.getMessage());
        }
    }

    public boolean verifySnapshot(Path input, String expectedHash) {
        return fileHash(input).equals(expectedHash);
    }

    public String snapshotJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"exportedAt\":\"").append(Instant.now()).append("\",");
        sb.append("\"counts\":{")
                .append("\"users\":").append(users.findAll().size()).append(',')
                .append("\"dataObjects\":").append(data.findAll().size()).append(',')
                .append("\"grants\":").append(grants.findAll().size()).append(',')
                .append("\"packages\":").append(packages.findAll().size()).append(',')
                .append("\"auditEvents\":").append(audit.findAll().size())
                .append("},");
        appendUsers(sb);
        sb.append(',');
        appendData(sb);
        sb.append(',');
        appendGrants(sb);
        sb.append(',');
        appendPackages(sb);
        sb.append(',');
        appendAudit(sb);
        sb.append('}');
        return sb.toString();
    }

    private void appendUsers(StringBuilder sb) {
        sb.append("\"users\":[");
        int i = 0;
        for (User user : users.findAll()) {
            comma(sb, i++);
            sb.append("{\"userId\":\"").append(json(user.userId())).append("\",\"role\":\"")
                    .append(user.role()).append("\",\"status\":\"").append(user.status()).append("\"}");
        }
        sb.append(']');
    }

    private String usersJson() {
        StringBuilder sb = new StringBuilder();
        appendUsers(sb);
        return "{" + sb + "}";
    }

    private String dataJson() {
        StringBuilder sb = new StringBuilder();
        appendData(sb);
        return "{" + sb + "}";
    }

    private String grantsJson() {
        StringBuilder sb = new StringBuilder();
        appendGrants(sb);
        return "{" + sb + "}";
    }

    private String packagesJson() {
        StringBuilder sb = new StringBuilder();
        appendPackages(sb);
        return "{" + sb + "}";
    }

    private String auditJson() {
        StringBuilder sb = new StringBuilder();
        appendAudit(sb);
        return "{" + sb + "}";
    }

    private static void writePart(Path path, String content) throws IOException {
        Files.writeString(path, content);
    }

    private void appendData(StringBuilder sb) {
        sb.append("\"dataObjects\":[");
        int i = 0;
        for (EncryptedDataPackage item : data.findAll()) {
            comma(sb, i++);
            sb.append("{\"dataId\":\"").append(json(item.dataId())).append("\",\"ownerId\":\"")
                    .append(json(item.ownerId())).append("\",\"contentKeyVersion\":").append(item.contentKeyVersion())
                    .append(",\"ciphertextHash\":\"").append(json(item.ciphertextHash())).append("\"}");
        }
        sb.append(']');
    }

    private void appendGrants(StringBuilder sb) {
        sb.append("\"grants\":[");
        int i = 0;
        for (ShareGrant grant : grants.findAll()) {
            comma(sb, i++);
            sb.append("{\"grantId\":\"").append(json(grant.grantId())).append("\",\"dataId\":\"")
                    .append(json(grant.dataId())).append("\",\"recipientId\":\"").append(json(grant.recipientId()))
                    .append("\",\"status\":\"").append(grant.status()).append("\",\"accessCount\":")
                    .append(grant.accessCount()).append(",\"downloadCount\":").append(grant.downloadCount())
                    .append(",\"decryptCount\":").append(grant.decryptCount()).append('}');
        }
        sb.append(']');
    }

    private void appendPackages(StringBuilder sb) {
        sb.append("\"packages\":[");
        int i = 0;
        for (ReEncryptedPackage item : packages.findAll()) {
            comma(sb, i++);
            sb.append("{\"packageId\":\"").append(json(item.packageId())).append("\",\"grantId\":\"")
                    .append(json(item.grantId())).append("\",\"status\":\"").append(item.status())
                    .append("\",\"contentKeyVersion\":").append(item.contentKeyVersion()).append('}');
        }
        sb.append(']');
    }

    private void appendAudit(StringBuilder sb) {
        sb.append("\"auditEvents\":[");
        int i = 0;
        for (AuditEvent event : audit.findAll()) {
            comma(sb, i++);
            sb.append("{\"eventId\":\"").append(json(event.eventId())).append("\",\"action\":\"")
                    .append(json(event.action())).append("\",\"success\":").append(event.success()).append('}');
        }
        sb.append(']');
    }

    private static void comma(StringBuilder sb, int index) {
        if (index > 0) {
            sb.append(',');
        }
    }

    private static String json(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
