package com.example.pre.crypto.ecc;

import java.math.BigInteger;

public record EccPoint(BigInteger x, BigInteger y, boolean infinity) {
    public static final EccPoint INFINITY = new EccPoint(BigInteger.ZERO, BigInteger.ZERO, true);

    public static EccPoint of(BigInteger x, BigInteger y) {
        return new EccPoint(x, y, false);
    }
}
