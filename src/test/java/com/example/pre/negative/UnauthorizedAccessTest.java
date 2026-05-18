package com.example.pre.negative;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.User;
import com.example.pre.service.DataSecurityService;
import com.example.pre.service.UserService;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class UnauthorizedAccessTest {
    @Test
    void recipientCannotDecryptBeforeAuthorization() {
        EccPreScheme scheme = new EccPreScheme();
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        UserService users = new UserService(scheme, new InMemoryUserRepository(), audit);
        DataSecurityService data = new DataSecurityService(scheme, new InMemoryDataRepository(), audit);

        User alice = users.createUser("Alice");
        User bob = users.createUser("Bob");
        EncryptedDataPackage uploaded = data.upload(alice, Bytes.utf8("private"));

        assertThrows(RuntimeException.class, () -> data.decryptOriginal(bob, uploaded));
    }
}
