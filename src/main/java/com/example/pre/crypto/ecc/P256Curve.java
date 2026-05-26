package com.example.pre.crypto.ecc;

import com.example.pre.util.Bytes;

import java.math.BigInteger;
import java.util.Arrays;

public final class P256Curve {
    public static final int FIELD_BYTES = 32;
    public static final BigInteger P = new BigInteger(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    public static final BigInteger A = new BigInteger(
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
    public static final BigInteger B = new BigInteger(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    public static final BigInteger N = new BigInteger(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    public static final EccPoint G = EccPoint.of(
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
    );

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    public EccPoint add(EccPoint p, EccPoint q) {
        if (p.infinity()) {
            return q;
        }
        if (q.infinity()) {
            return p;
        }
        if (p.x().equals(q.x())) {
            if (mod(p.y().add(q.y())).equals(BigInteger.ZERO)) {
                return EccPoint.INFINITY;
            }
            return doublePoint(p);
        }
        BigInteger lambda = mod(q.y().subtract(p.y()))
                .multiply(mod(q.x().subtract(p.x())).modInverse(P))
                .mod(P);
        BigInteger xr = mod(lambda.multiply(lambda).subtract(p.x()).subtract(q.x()));
        BigInteger yr = mod(lambda.multiply(p.x().subtract(xr)).subtract(p.y()));
        return EccPoint.of(xr, yr);
    }

    public EccPoint doublePoint(EccPoint p) {
        if (p.infinity() || p.y().equals(BigInteger.ZERO)) {
            return EccPoint.INFINITY;
        }
        BigInteger numerator = mod(THREE.multiply(p.x()).multiply(p.x()).add(A));
        BigInteger denominator = TWO.multiply(p.y()).mod(P).modInverse(P);
        BigInteger lambda = numerator.multiply(denominator).mod(P);
        BigInteger xr = mod(lambda.multiply(lambda).subtract(TWO.multiply(p.x())));
        BigInteger yr = mod(lambda.multiply(p.x().subtract(xr)).subtract(p.y()));
        return EccPoint.of(xr, yr);
    }

    public EccPoint multiply(BigInteger scalar, EccPoint point) {
        BigInteger k = scalar.mod(N);
        EccPoint result = EccPoint.INFINITY;
        EccPoint addend = point;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                result = add(result, addend);
            }
            addend = doublePoint(addend);
            k = k.shiftRight(1);
        }
        return result;
    }

    public boolean isOnCurve(EccPoint point) {
        if (point.infinity()) {
            return false;
        }
        BigInteger left = point.y().multiply(point.y()).mod(P);
        BigInteger right = point.x().multiply(point.x()).multiply(point.x())
                .add(A.multiply(point.x()))
                .add(B)
                .mod(P);
        return left.equals(right);
    }

    public byte[] encode(EccPoint point) {
        if (point.infinity()) {
            throw new IllegalArgumentException("cannot encode point at infinity");
        }
        return Bytes.concat(
                new byte[]{0x04},
                Bytes.unsignedFixed(point.x(), FIELD_BYTES),
                Bytes.unsignedFixed(point.y(), FIELD_BYTES)
        );
    }

    public EccPoint decode(byte[] encoded) {
        if (encoded.length != 1 + 2 * FIELD_BYTES || encoded[0] != 0x04) {
            throw new IllegalArgumentException("expected uncompressed P-256 point");
        }
        BigInteger x = Bytes.positiveBigInteger(Arrays.copyOfRange(encoded, 1, 1 + FIELD_BYTES));
        BigInteger y = Bytes.positiveBigInteger(Arrays.copyOfRange(encoded, 1 + FIELD_BYTES, encoded.length));
        if (x.signum() < 0 || x.compareTo(P) >= 0 || y.signum() < 0 || y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("P-256 point coordinates must be canonical field elements");
        }
        EccPoint point = EccPoint.of(x, y);
        if (!isOnCurve(point)) {
            throw new IllegalArgumentException("point is not on P-256");
        }
        return point;
    }

    private static BigInteger mod(BigInteger value) {
        BigInteger out = value.mod(P);
        return out.signum() < 0 ? out.add(P) : out;
    }
}
