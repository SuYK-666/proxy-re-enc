package com.example.pre.crypto;

import com.example.pre.model.AlgorithmType;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

public final class ScopedReEncryptionKey implements ReEncryptionKey {
    private final ReEncryptionKey delegate;
    private final String grantId;
    private final String dataId;
    private final String recipientId;
    private final int ownerKeyVersion;
    private final String policyHash;
    private final Instant expiresAt;
    private final int maxUsage;
    private final AtomicInteger usage = new AtomicInteger();

    public ScopedReEncryptionKey(ReEncryptionKey delegate, String grantId, String dataId, String recipientId,
                                 int ownerKeyVersion, String policyHash, Instant expiresAt, int maxUsage) {
        if (maxUsage < 1) {
            throw new IllegalArgumentException("maxUsage must be positive");
        }
        this.delegate = delegate;
        this.grantId = grantId;
        this.dataId = dataId;
        this.recipientId = recipientId;
        this.ownerKeyVersion = ownerKeyVersion;
        this.policyHash = policyHash;
        this.expiresAt = expiresAt;
        this.maxUsage = maxUsage;
    }

    @Override
    public AlgorithmType algorithm() {
        return delegate.algorithm();
    }

    public ReEncryptionKey consume(String actualGrantId, String actualDataId, String actualRecipientId,
                                   int actualKeyVersion, String actualPolicyHash, Instant now) {
        if (!grantId.equals(actualGrantId) || !dataId.equals(actualDataId)
                || !recipientId.equals(actualRecipientId) || ownerKeyVersion != actualKeyVersion
                || !policyHash.equals(actualPolicyHash)) {
            throw new IllegalArgumentException("re-encryption key scope mismatch");
        }
        if (expiresAt != null && !expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("re-encryption key expired");
        }
        int current;
        do {
            current = usage.get();
            if (current >= maxUsage) {
                throw new IllegalArgumentException("re-encryption key usage exhausted");
            }
        } while (!usage.compareAndSet(current, current + 1));
        return delegate;
    }

    public int usageCount() {
        return usage.get();
    }
}
