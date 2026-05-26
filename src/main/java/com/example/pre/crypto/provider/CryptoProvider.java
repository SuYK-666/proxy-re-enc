package com.example.pre.crypto.provider;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.UserKeyPair;

public interface CryptoProvider {
    SchemeDescriptor descriptor();

    UserKeyPair generateKeyPair(String userId);

    EncryptedKeyCapsule encapsulate(byte[] dek, PublicKeyMaterial recipient, CapsuleContext context);

    EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule capsule, ReEncryptionKey reKey, CapsuleContext context);

    byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial recipientPrivateKey, CapsuleContext context);
}
