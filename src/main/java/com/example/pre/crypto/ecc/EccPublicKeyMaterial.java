package com.example.pre.crypto.ecc;

import com.example.pre.crypto.PublicKeyMaterial;

public record EccPublicKeyMaterial(EccPoint point) implements PublicKeyMaterial {
}
