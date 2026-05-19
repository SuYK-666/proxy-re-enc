package com.example.pre.crypto.rsa;

import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.util.Bytes;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public record RsaPublicKeyMaterial(BigInteger modulus, BigInteger exponent) implements PublicKeyMaterial {
    @Override
    public byte[] encoded() {
        byte[] prefix = "RSA".getBytes(StandardCharsets.UTF_8);
        byte[] n = Bytes.unsignedFixed(modulus, (modulus.bitLength() + 7) / 8);
        byte[] e = Bytes.unsignedFixed(exponent, (exponent.bitLength() + 7) / 8);
        return Bytes.concat(prefix, n, e);
    }
}
