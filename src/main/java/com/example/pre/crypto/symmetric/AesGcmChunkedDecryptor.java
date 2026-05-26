package com.example.pre.crypto.symmetric;

import com.example.pre.crypto.hash.Hash;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class AesGcmChunkedDecryptor {
    private AesGcmChunkedDecryptor() {
    }

    public static void decryptAndVerify(
            InputStream input,
            OutputStream output,
            byte[] key,
            byte[] baseAad,
            AesGcmChunkedEncryptor.Manifest manifest,
            String expectedMerkleRoot
    ) throws IOException {
        if (!MerkleChunkTree.root(manifest).equals(expectedMerkleRoot)) {
            throw new IllegalArgumentException("chunk manifest Merkle root mismatch");
        }
        for (AesGcmChunkedEncryptor.ChunkRecord chunk : manifest.chunks()) {
            byte[] ciphertext = input.readNBytes(chunk.ciphertextBytes());
            if (ciphertext.length != chunk.ciphertextBytes()
                    || !Hash.sha256Hex(ciphertext).equals(chunk.ciphertextHash())) {
                throw new IllegalArgumentException("chunk ciphertext mismatch at index " + chunk.index());
            }
            byte[] plaintext = AesGcm.decrypt(key, chunk.nonce(), ciphertext, chunkAad(baseAad, chunk.index()));
            if (plaintext.length != chunk.plaintextBytes()) {
                throw new IllegalArgumentException("chunk plaintext length mismatch at index " + chunk.index());
            }
            output.write(plaintext);
            Arrays.fill(plaintext, (byte) 0);
        }
        if (input.read() != -1) {
            throw new IllegalArgumentException("unexpected trailing ciphertext data");
        }
    }

    private static byte[] chunkAad(byte[] baseAad, int index) {
        byte[] prefix = ("ReKeyShare-Chunk-v1|" + index + "|").getBytes(StandardCharsets.UTF_8);
        ByteBuffer out = ByteBuffer.allocate(prefix.length + (baseAad == null ? 0 : baseAad.length));
        out.put(prefix);
        if (baseAad != null) {
            out.put(baseAad);
        }
        return out.array();
    }
}
