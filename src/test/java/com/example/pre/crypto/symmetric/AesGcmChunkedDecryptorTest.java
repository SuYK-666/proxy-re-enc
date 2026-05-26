package com.example.pre.crypto.symmetric;

import com.example.pre.util.Bytes;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmChunkedDecryptorTest {
    @Test
    void decryptsMultiChunkContentAndLocatesTampering() throws Exception {
        byte[] plaintext = SecureRandomUtil.randomBytes(3 * 1024 * 1024 + 37);
        byte[] key = SecureRandomUtil.randomBytes(AesGcm.KEY_BYTES);
        byte[] aad = Bytes.utf8("large-file:data-1:v1");
        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        var manifest = AesGcmChunkedEncryptor.encrypt(new ByteArrayInputStream(plaintext), encrypted, key, aad,
                1024 * 1024);
        String root = MerkleChunkTree.root(manifest);

        ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
        AesGcmChunkedDecryptor.decryptAndVerify(new ByteArrayInputStream(encrypted.toByteArray()), decrypted,
                key, aad, manifest, root);
        assertArrayEquals(plaintext, decrypted.toByteArray());

        byte[] damaged = encrypted.toByteArray();
        damaged[damaged.length / 2] ^= 1;
        assertThrows(IllegalArgumentException.class,
                () -> AesGcmChunkedDecryptor.decryptAndVerify(new ByteArrayInputStream(damaged),
                        new ByteArrayOutputStream(), key, aad, manifest, root));
    }
}
