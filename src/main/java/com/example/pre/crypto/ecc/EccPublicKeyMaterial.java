package com.example.pre.crypto.ecc;

import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.util.Bytes;

import java.nio.charset.StandardCharsets;

public record EccPublicKeyMaterial(EccPoint point) implements PublicKeyMaterial {
    @Override
    public byte[] encoded() {
        byte[] prefix = "ECC-P-256".getBytes(StandardCharsets.UTF_8);
        byte[] x = Bytes.unsignedFixed(point.x(), 32);
        byte[] y = Bytes.unsignedFixed(point.y(), 32);
        return Bytes.concat(prefix, x, y);
    }
}
