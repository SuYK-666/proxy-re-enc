package com.example.pre.crypto;

import com.example.pre.model.AlgorithmType;

public record EncryptedKeyCapsule(
        AlgorithmType algorithm,
        byte[] header,
        byte[] wrappedKey,
        byte[] keyNonce
) {
}
