package com.example.pre.model;

import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;

public record UserKeyPair(
        String userId,
        PublicKeyMaterial publicKey,
        PrivateKeyMaterial privateKey
) {
}
