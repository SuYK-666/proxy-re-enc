package com.example.pre.service;

import com.example.pre.crypto.ecc.EccInteractiveReKeyGenerator;
import com.example.pre.crypto.ecc.EccPrivateKeyMaterial;
import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.crypto.ecc.ReKeySessionContext;
import com.example.pre.model.User;

public final class DemoPrivateKeyStore {
    private DemoPrivateKeyStore() {
    }

    public static RecipientReKeyShare createEccRecipientShareLocally(User recipient, ReKeySessionContext context) {
        if (!(recipient.keyPair().privateKey() instanceof EccPrivateKeyMaterial recipientPrivate)) {
            throw new ReKeyShareException(ErrorCode.INVALID_RECIPIENT_SHARE, "recipient does not hold an ECC demo key");
        }
        return new EccInteractiveReKeyGenerator().createRecipientShare(recipientPrivate, context);
    }
}
