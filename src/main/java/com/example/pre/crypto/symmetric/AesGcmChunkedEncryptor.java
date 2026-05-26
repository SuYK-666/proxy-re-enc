package com.example.pre.crypto.symmetric;

import com.example.pre.crypto.hash.Hash;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

public final class AesGcmChunkedEncryptor {
    public static final int DEFAULT_CHUNK_BYTES = 1024 * 1024;

    public record ChunkRecord(int index, byte[] nonce, int plaintextBytes, int ciphertextBytes, String ciphertextHash) {
    }

    public record Manifest(int chunkSize, long totalPlaintextBytes, long totalCiphertextBytes, List<ChunkRecord> chunks) {
    }

    private AesGcmChunkedEncryptor() {
    }

    public static Manifest encrypt(InputStream input, OutputStream output, byte[] key, byte[] baseAad) throws IOException {
        return encrypt(input, output, key, baseAad, DEFAULT_CHUNK_BYTES);
    }

    public static Manifest encrypt(InputStream input, OutputStream output, byte[] key, byte[] baseAad, int chunkSize) throws IOException {
        byte[] buffer = new byte[chunkSize];
        int index = 0;
        long plainTotal = 0;
        long cipherTotal = 0;
        List<ChunkRecord> chunks = new ArrayList<>();
        while (true) {
            int read = input.read(buffer);
            if (read < 0) {
                break;
            }
            byte[] plaintextChunk = java.util.Arrays.copyOf(buffer, read);
            AesGcm.CipherText encrypted = AesGcm.encrypt(key, plaintextChunk, chunkAad(baseAad, index));
            output.write(encrypted.ciphertext());
            chunks.add(new ChunkRecord(index, encrypted.nonce(), read, encrypted.ciphertext().length,
                    Hash.sha256Hex(encrypted.ciphertext())));
            plainTotal += read;
            cipherTotal += encrypted.ciphertext().length;
            java.util.Arrays.fill(plaintextChunk, (byte) 0);
            index++;
        }
        return new Manifest(chunkSize, plainTotal, cipherTotal, List.copyOf(chunks));
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

    public static String manifestHash(Manifest manifest) {
        StringBuilder sb = new StringBuilder();
        sb.append(manifest.chunkSize()).append('|').append(manifest.totalPlaintextBytes()).append('|')
                .append(manifest.totalCiphertextBytes());
        for (ChunkRecord chunk : manifest.chunks()) {
            sb.append('|').append(chunk.index()).append(':')
                    .append(HexFormat.of().formatHex(chunk.nonce())).append(':')
                    .append(chunk.plaintextBytes()).append(':')
                    .append(chunk.ciphertextBytes()).append(':')
                    .append(chunk.ciphertextHash());
        }
        return Hash.sha256Hex(sb.toString().getBytes(StandardCharsets.UTF_8));
    }
}
