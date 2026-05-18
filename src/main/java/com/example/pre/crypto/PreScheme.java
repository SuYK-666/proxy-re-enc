package com.example.pre.crypto;

import com.example.pre.model.UserKeyPair;

public interface PreScheme {
    String name();

    UserKeyPair generateKeyPair(String userId);

    EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial ownerPublicKey);

    byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey);

    EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey);
}
