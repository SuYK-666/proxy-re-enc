package com.example.pre.crypto.envelope;

import com.example.pre.crypto.PublicKeyMaterial;

public record SecureEnvelopePublicKey(byte[] encoded) implements PublicKeyMaterial {
    public SecureEnvelopePublicKey {
        encoded = encoded.clone();
    }

    @Override
    public byte[] encoded() {
        return encoded.clone();
    }
}
