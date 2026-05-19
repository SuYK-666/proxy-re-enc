package com.example.pre.service;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryReEncryptedPackageRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class StorageSnapshotServiceTest {
    @Test
    void exportsJsonSnapshotWithManagedObjectCounts() throws Exception {
        EccPreScheme scheme = new EccPreScheme();
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        InMemoryUserRepository users = new InMemoryUserRepository();
        InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        InMemoryGrantRepository grantRepository = new InMemoryGrantRepository();
        InMemoryReEncryptedPackageRepository packageRepository = new InMemoryReEncryptedPackageRepository();

        UserService userService = new UserService(scheme, users, audit);
        DataSecurityService data = new DataSecurityService(scheme, dataRepository, audit);
        var alice = userService.createUser("Alice");
        data.upload(alice, Bytes.utf8("snapshot"));

        StorageSnapshotService storage = new StorageSnapshotService(
                users, dataRepository, grantRepository, packageRepository, audit);
        Path output = Path.of("target", "storage-test", "snapshot.json");
        String snapshotHash = storage.exportSnapshotHash(output);

        String json = Files.readString(output);
        assertTrue(json.contains("\"users\":1"));
        assertTrue(json.contains("\"dataObjects\":1"));
        assertTrue(json.contains("\"auditEvents\""));
        assertTrue(storage.verifySnapshot(output, snapshotHash));

        Path manifest = storage.exportRepositoryFiles(Path.of("target", "storage-test", "repository"));
        assertTrue(Files.exists(manifest));
        assertTrue(Files.readString(manifest).contains("\"usersHash\""));
    }
}
