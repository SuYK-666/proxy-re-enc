package com.example.pre.service;

import com.example.pre.crypto.hash.Hash;
import com.example.pre.crypto.threshold.ThresholdReKeyShare;
import com.example.pre.crypto.threshold.ThresholdSecretSharing;
import com.example.pre.util.Bytes;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ThresholdReEncryptionService {
    public record SignedShare(
            String proxyId,
            ThresholdReKeyShare share,
            String shareDigest,
            String signatureAlgorithm,
            String publicKey,
            String signature
    ) {
    }

    private final Map<String, KeyPair> proxyKeys = new HashMap<>();

    public List<ThresholdReKeyShare> splitForProxies(byte[] reKeyMaterial, int threshold, List<String> proxyIds) {
        if (proxyIds == null || proxyIds.size() < threshold || new HashSet<>(proxyIds).size() != proxyIds.size()) {
            throw new IllegalArgumentException("threshold requires unique proxy assignments");
        }
        for (String proxyId : proxyIds) {
            proxyKeys.computeIfAbsent(proxyId, ignored -> keyPair());
        }
        return ThresholdSecretSharing.split(reKeyMaterial, threshold, proxyIds.size());
    }

    public SignedShare convertShare(String proxyId, ThresholdReKeyShare share) {
        KeyPair keyPair = proxyKeys.get(proxyId);
        if (keyPair == null) {
            throw new ReKeyShareException(ErrorCode.PROXY_INACTIVE, "proxy has no assigned threshold share");
        }
        String digest = shareDigest(proxyId, share);
        return new SignedShare(proxyId, share, digest, "Ed25519",
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()), sign(keyPair, digest));
    }

    public byte[] aggregate(List<SignedShare> submitted) {
        if (submitted == null || submitted.isEmpty()) {
            throw new ReKeyShareException(ErrorCode.THRESHOLD_NOT_REACHED, "no threshold shares submitted");
        }
        Set<String> proxyIds = new HashSet<>();
        List<ThresholdReKeyShare> verified = new ArrayList<>();
        for (SignedShare signed : submitted) {
            if (!proxyIds.add(signed.proxyId()) || !verifyShare(signed)) {
                throw new ReKeyShareException(ErrorCode.THRESHOLD_SHARE_INVALID, "threshold share proof invalid");
            }
            verified.add(signed.share());
        }
        try {
            return ThresholdSecretSharing.combine(verified);
        } catch (IllegalArgumentException e) {
            throw new ReKeyShareException(ErrorCode.THRESHOLD_NOT_REACHED, "threshold has not been reached");
        }
    }

    public boolean verifyShare(SignedShare signed) {
        try {
            KeyPair expected = proxyKeys.get(signed.proxyId());
            if (expected == null || !"Ed25519".equals(signed.signatureAlgorithm())
                    || !signed.shareDigest().equals(shareDigest(signed.proxyId(), signed.share()))
                    || !java.security.MessageDigest.isEqual(expected.getPublic().getEncoded(),
                    Base64.getDecoder().decode(signed.publicKey()))) {
                return false;
            }
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(expected.getPublic());
            verifier.update(signed.shareDigest().getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(signed.signature()));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    private static String shareDigest(String proxyId, ThresholdReKeyShare share) {
        return Hash.sha256Hex(Bytes.concat(Bytes.utf8("threshold-share-v1|" + proxyId + "|"
                + share.threshold() + "|" + share.totalShares() + "|" + share.index() + "|"), share.value()));
    }

    private static String sign(KeyPair keyPair, String payload) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot sign threshold share", e);
        }
    }

    private static KeyPair keyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is not available", e);
        }
    }
}
