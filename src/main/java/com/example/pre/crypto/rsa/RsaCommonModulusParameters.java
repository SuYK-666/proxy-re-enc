package com.example.pre.crypto.rsa;

import com.example.pre.util.SecureRandomUtil;

import java.math.BigInteger;

public record RsaCommonModulusParameters(
        BigInteger modulus,
        BigInteger phi,
        BigInteger sharedExponentFactor
) {
    private static final BigInteger DEFAULT_H = BigInteger.valueOf(65537);

    public static RsaCommonModulusParameters generate(int bits) {
        if (bits < 1024) {
            throw new IllegalArgumentException("RSA modulus should be at least 1024 bits for this demo");
        }
        while (true) {
            BigInteger p = BigInteger.probablePrime(bits / 2, SecureRandomUtil.random());
            BigInteger q = BigInteger.probablePrime(bits - bits / 2, SecureRandomUtil.random());
            if (p.equals(q)) {
                continue;
            }
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            if (DEFAULT_H.gcd(phi).equals(BigInteger.ONE)) {
                return new RsaCommonModulusParameters(p.multiply(q), phi, DEFAULT_H);
            }
        }
    }

    public int modulusBytes() {
        return (modulus.bitLength() + 7) / 8;
    }
}
