package com.example.pre.crypto.envelope;

import com.example.pre.crypto.PrivateKeyMaterial;

public record SecureEnvelopePrivateKey(byte[] encoded) implements PrivateKeyMaterial {
    public SecureEnvelopePrivateKey {
        encoded = encoded.clone();
    }

    @Override
    public byte[] encoded() {
        return encoded.clone();
    }

    @Override
    public String toString() {
        return "SecureEnvelopePrivateKey[<redacted>]";
    }
}
