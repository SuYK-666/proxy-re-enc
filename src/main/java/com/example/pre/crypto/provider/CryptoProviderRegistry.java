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

    public List<SchemeDescriptor> descriptors() {
        return providers.values().stream().map(CryptoProvider::descriptor).toList();
    }

    public CryptoProvider productionDefault() {
        return providers.values().stream()
                .filter(provider -> provider.descriptor().allowedAsProductionDefault())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("production requires a non-baseline crypto provider"));
    }
}
