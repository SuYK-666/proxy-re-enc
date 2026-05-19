package com.example.pre.model;

import com.example.pre.crypto.PrivateKeyMaterial;
import com.example.pre.crypto.PublicKeyMaterial;
import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.crypto.ecc.ReKeySessionContext;

public record ReKeyGenerationRequest(
        String grantId,
        String ownerKeyId,
        String recipientKeyId,
        AlgorithmType algorithm,
        String policyHash,
        PrivateKeyMaterial ownerPrivateKey,
        PublicKeyMaterial recipientPublicKey,
        RecipientReKeyShare recipientShare,
        ReKeySessionContext sessionContext
) {
}
