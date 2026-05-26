package com.example.pre.crypto.ecc;

import com.example.pre.crypto.ReEncryptionKey;
import com.example.pre.model.AlgorithmType;

import java.math.BigInteger;

public record EccReEncryptionKey(BigInteger scalar) implements ReEncryptionKey {
    @Override
    public AlgorithmType algorithm() {
        return AlgorithmType.ECC_PRE;
    }
}
