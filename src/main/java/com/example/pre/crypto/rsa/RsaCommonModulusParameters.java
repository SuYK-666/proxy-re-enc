package com.example.pre.crypto.rsa;

import com.example.pre.util.SecureRandomUtil;

import java.math.BigInteger;

public final class RsaCommonModulusParameters {
    private static final BigInteger DEFAULT_H = BigInteger.valueOf(65537);
    public static final int MIN_DEMO_BITS = 1024;
    public static final int MIN_PRODUCTION_BITS = 2048;

    private final BigInteger modulus;
    private final BigInteger phi;
    private final BigInteger sharedExponentFactor;

    private RsaCommonModulusParameters(BigInteger modulus, BigInteger phi, BigInteger sharedExponentFactor) {
        this.modulus = modulus;
        this.phi = phi;
        this.sharedExponentFactor = sharedExponentFactor;
    }

    public static RsaCommonModulusParameters generate(int bits) {
        if (bits < MIN_DEMO_BITS) {
            throw new IllegalArgumentException("RSA modulus should be at least 1024 bits for insecure demo benchmarks");
        }
        return generateInternal(bits);
    }

    public static RsaCommonModulusParameters generateProduction(int bits) {
        if (bits < MIN_PRODUCTION_BITS) {
            throw new IllegalArgumentException("production RSA modulus must be at least 2048 bits");
        }
        return generateInternal(bits);
    }

    private static RsaCommonModulusParameters generateInternal(int bits) {
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

    public BigInteger modulus() {
        return modulus;
    }

    BigInteger phi() {
        return phi;
    }

    public BigInteger sharedExponentFactor() {
        return sharedExponentFactor;
    }

    public int modulusBytes() {
        return (modulus.bitLength() + 7) / 8;
    }
}
