package com.example.pre.crypto.ecc;

import com.example.pre.crypto.PrivateKeyMaterial;

import java.math.BigInteger;

public record EccPrivateKeyMaterial(BigInteger scalar) implements PrivateKeyMaterial {
}
