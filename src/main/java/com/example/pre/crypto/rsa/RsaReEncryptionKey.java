package com.example.pre.crypto.rsa;

import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.model.AlgorithmType;

import java.math.BigInteger;

public record RsaReEncryptionKey(BigInteger modulus, BigInteger exponent) implements ReEncryptionKey {
    @Override
    public AlgorithmType algorithm() {
        return AlgorithmType.RSA_PRE;
    }

    @Override
    public String toString() {
        return "RsaReEncryptionKey[<redacted>]";
    }
}
