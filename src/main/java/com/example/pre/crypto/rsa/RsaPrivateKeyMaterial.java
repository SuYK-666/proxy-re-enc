package com.example.pre.crypto.rsa;

import com.example.pre.crypto.PrivateKeyMaterial;

import java.math.BigInteger;

public record RsaPrivateKeyMaterial(
        BigInteger modulus,
        BigInteger privateExponent,
        BigInteger phi
) implements PrivateKeyMaterial {
}
