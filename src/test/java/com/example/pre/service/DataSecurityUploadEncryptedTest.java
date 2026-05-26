package com.example.pre.service;

import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DataSecurityUploadEncryptedTest {
    @Test
    void acceptsOwnerPreparedCiphertextAndRejectsMissingMaterials() {
        RsaPreScheme scheme = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        InMemoryAuditRepository audit = new InMemoryAuditRepository();
        DataSecurityService service = new DataSecurityService(scheme, new InMemoryDataRepository(), audit);
        var owner = new UserService(scheme, new InMemoryUserRepository(), audit).createUser("alice");
        var encrypted = service.upload(owner, Bytes.utf8("owner-prepared"));
        var context = DataSecurityService.capsuleContext(encrypted);

        var accepted = service.uploadEncrypted(new DataSecurityService.UploadEncryptedCommand(owner,
                encrypted.encryptedContent(), encrypted.contentNonce(), encrypted.aad(), encrypted.originalCapsule(),
                context, encrypted.originalSize(), encrypted.fileName(), encrypted.contentType()));
        assertEquals(encrypted.dataId(), accepted.dataId());

        assertInvalid(service, owner, null, encrypted.contentNonce(), encrypted.aad(), encrypted.originalCapsule(), context);
        assertInvalid(service, owner, encrypted.encryptedContent(), null, encrypted.aad(), encrypted.originalCapsule(), context);
        assertInvalid(service, owner, encrypted.encryptedContent(), encrypted.contentNonce(), null, encrypted.originalCapsule(), context);
        assertInvalid(service, owner, encrypted.encryptedContent(), encrypted.contentNonce(), encrypted.aad(), null, context);
    }

    private static void assertInvalid(DataSecurityService service, com.example.pre.model.User owner,
                                      byte[] encrypted, byte[] nonce, byte[] aad,
                                      com.example.pre.crypto.EncryptedKeyCapsule capsule,
                                      com.example.pre.model.CapsuleContext context) {
        ReKeyShareException failure = assertThrows(ReKeyShareException.class,
                () -> service.uploadEncrypted(new DataSecurityService.UploadEncryptedCommand(owner, encrypted,
                        nonce, aad, capsule, context, 1, "invalid.bin", "application/octet-stream")));
        assertEquals(ErrorCode.INVALID_REQUEST, failure.code());
    }
}
