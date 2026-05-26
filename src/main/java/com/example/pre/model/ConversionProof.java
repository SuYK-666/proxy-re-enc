package com.example.pre.model;

import java.time.Instant;

public record ConversionProof(
        String proofVersion,
        String algorithmSuite,
        String objectDigest,
        String grantDigest,
        String capsuleDigest,
        String packageDigest,
        String proxyId,
        Instant issuedAt,
        String nonce,
        String signatureAlgorithm,
        String publicKey,
        String signature
) {
}
