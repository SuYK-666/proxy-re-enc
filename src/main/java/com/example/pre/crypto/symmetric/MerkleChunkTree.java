package com.example.pre.crypto.symmetric;

import com.example.pre.crypto.hash.Hash;
import com.example.pre.util.Bytes;

import java.util.ArrayList;
import java.util.List;

public final class MerkleChunkTree {
    private MerkleChunkTree() {
    }

    public static String root(AesGcmChunkedEncryptor.Manifest manifest) {
        List<String> level = manifest.chunks().stream()
                .map(chunk -> Hash.sha256Hex(Bytes.utf8(chunk.index() + "|" + chunk.ciphertextHash())))
                .toList();
        if (level.isEmpty()) {
            return Hash.sha256Hex(Bytes.utf8("EMPTY"));
        }
        while (level.size() > 1) {
            List<String> next = new ArrayList<>();
            for (int index = 0; index < level.size(); index += 2) {
                String left = level.get(index);
                String right = index + 1 < level.size() ? level.get(index + 1) : left;
                next.add(Hash.sha256Hex(Bytes.utf8(left + "|" + right)));
            }
            level = next;
        }
        return level.get(0);
    }
}
