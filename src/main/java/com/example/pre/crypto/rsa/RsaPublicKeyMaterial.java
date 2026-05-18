package com.example.pre.crypto.rsa;

import com.example.pre.crypto.PublicKeyMaterial;

import java.math.BigInteger;

public record RsaPublicKeyMaterial(BigInteger modulus, BigInteger exponent) implements PublicKeyMaterial {
}
