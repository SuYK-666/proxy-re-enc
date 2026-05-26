package com.example.pre.service;

import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.User;
import com.example.pre.crypto.rsa.RsaPublicKeyMaterial;

import java.util.EnumMap;
import java.util.Map;

public final class SchemeRegistry {
    private final Map<AlgorithmType, PreScheme> schemes = new EnumMap<>(AlgorithmType.class);

    public SchemeRegistry() {
        schemes.put(AlgorithmType.RSA_PRE, new RsaPreScheme(RsaCommonModulusParameters.generateProduction(3072)));
        schemes.put(AlgorithmType.ECC_PRE, new EccPreScheme());
    }

    public PreScheme get(AlgorithmType algorithm) {
        PreScheme scheme = schemes.get(algorithm);
        if (scheme == null) {
            throw new ReKeyShareException(ErrorCode.ALGORITHM_MISMATCH, "unsupported algorithm: " + algorithm);
        }
        return scheme;
    }

    public PreScheme forUser(User user) {
        return get(user.keyPair().publicKey() instanceof RsaPublicKeyMaterial
                ? AlgorithmType.RSA_PRE
                : AlgorithmType.ECC_PRE);
    }

    public AlgorithmType parse(String value, AlgorithmType fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return AlgorithmType.valueOf(value.trim().toUpperCase());
    }
}
