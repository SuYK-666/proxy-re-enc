package com.example.pre.crypto.provider;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class CryptoProviderRegistry {
    private final Map<String, CryptoProvider> providers = new LinkedHashMap<>();

    public CryptoProviderRegistry() {
        register(new BaselineRsaProvider(2048));
        register(new BaselineEccProvider());
        register(new SecureEnvelopeProvider());
    }

    public void register(CryptoProvider provider) {
        providers.put(provider.descriptor().schemeId(), provider);
    }

    public CryptoProvider require(String schemeId) {
        CryptoProvider provider = providers.get(schemeId);
        if (provider == null) {
            throw new IllegalArgumentException("unknown schemeId: " + schemeId);
        }
        return provider;
    }

    public CryptoProvider require(CryptoProfile profile, String schemeId) {
        CryptoProvider provider = require(schemeId);
        CryptoProfileGuard.assertAllowed(profile, provider.descriptor());
        return provider;
    }

    public List<SchemeDescriptor> descriptors() {
        return providers.values().stream().map(CryptoProvider::descriptor).toList();
    }

    public CryptoProvider productionDefault() {
        CryptoProvider provider = providers.values().stream()
                .filter(candidate -> candidate.descriptor().allowedAsProductionDefault())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("production requires a non-baseline crypto provider"));
        CryptoProfileGuard.assertAllowed(CryptoProfile.productionDefault(), provider.descriptor());
        return provider;
    }
}
