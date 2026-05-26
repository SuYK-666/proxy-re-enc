package com.example.pre.storage;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.User;
import com.example.pre.model.UserRole;
import com.example.pre.model.UserStatus;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JdbcGovernanceRepositoryTest {
    @Test
    void recoversGovernanceStateAndAtomicallyEnforcesAccessLimit() throws Exception {
        String url = "jdbc:h2:mem:governance-recovery;DB_CLOSE_DELAY=-1";
        JdbcGovernanceRepository first = new JdbcGovernanceRepository(url, "sa", "");
        Fixture fixture = fixture(3);
        first.saveWorkflow("tenant-a", fixture.owner(), fixture.recipient(), fixture.data(), fixture.grant(), fixture.dataPackage());

        JdbcGovernanceRepository restarted = new JdbcGovernanceRepository(url, "sa", "");
        var executor = Executors.newFixedThreadPool(20);
        try {
            var results = new ArrayList<Future<Boolean>>();
            for (int index = 0; index < 100; index++) {
                results.add(executor.submit(() -> restarted.consumeGrantAccess("tenant-a", fixture.grant().grantId())));
            }
            int accepted = 0;
            for (Future<Boolean> result : results) {
                if (result.get()) {
                    accepted++;
                }
            }
            assertEquals(3, accepted);
        } finally {
            executor.shutdownNow();
        }

        JdbcGovernanceRepository.RecoverySnapshot active = restarted.snapshot(
                "tenant-a", fixture.grant().grantId(), fixture.dataPackage().packageId());
        assertEquals(1, active.dataObjects());
        assertEquals(1, active.grants());
        assertEquals(1, active.packages());
        assertEquals(3, active.accessCount());
        assertEquals("ACTIVE", active.packageStatus());

        restarted.revokeAndInvalidate("tenant-a", fixture.grant().grantId());
        assertEquals("INVALIDATED", restarted.snapshot(
                "tenant-a", fixture.grant().grantId(), fixture.dataPackage().packageId()).packageStatus());
    }

    private static Fixture fixture(int maxAccess) {
        User owner = new User("alice", null, "alice", UserRole.OWNER, UserStatus.ACTIVE, Instant.now());
        User recipient = new User("bob", null, "bob", UserRole.RECIPIENT, UserStatus.ACTIVE, Instant.now());
        EncryptedKeyCapsule capsule = new EncryptedKeyCapsule(AlgorithmType.RSA_PRE, Bytes.utf8("header"),
                Bytes.utf8("wrapped"), Bytes.utf8("nonce-value12"));
        EncryptedDataPackage data = EncryptedDataPackage.uploadedEncrypted("data-1", owner.userId(),
                AlgorithmType.RSA_PRE, Bytes.utf8("ciphertext"), Bytes.utf8("nonce-value12"), Bytes.utf8("aad"),
                capsule, 10, "proof.bin", "application/octet-stream", "owner-key-v1", 1, "policy", "context");
        ShareGrant grant = ShareGrant.active(data.dataId(), owner.userId(), recipient.userId(), AlgorithmType.RSA_PRE,
                new AccessPolicy(true, true, false, maxAccess, Instant.now().plusSeconds(60), "research"),
                "policy", null, 1);
        ReEncryptedPackage dataPackage = new ReEncryptedPackage("package-1", grant.grantId(), data.dataId(),
                owner.userId(), recipient.userId(), AlgorithmType.RSA_PRE, data.encryptedContent(),
                data.contentNonce(), data.aad(), capsule, Instant.now(), 1, data.storagePath(), data.ownerKeyId(),
                data.policyHash(), grant.policyHash(), data.contextHash(), "grant-context", Bytes.utf8("grant-aad"),
                com.example.pre.model.PackageStatus.ACTIVE, null, "", "manifest");
        return new Fixture(owner, recipient, data, grant, dataPackage);
    }

    private record Fixture(User owner, User recipient, EncryptedDataPackage data, ShareGrant grant,
                           ReEncryptedPackage dataPackage) {
    }
}
