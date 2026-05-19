package com.example.pre.util;

import com.example.pre.model.CapsuleContext;

public final class AadBuilder {
    private AadBuilder() {
    }

    public static byte[] build(CapsuleContext context) {
        return Bytes.utf8(buildString(context));
    }

    public static String buildString(CapsuleContext context) {
        return lengthPrefix("dataId", context.dataId())
                + lengthPrefix("ownerId", context.ownerId())
                + lengthPrefix("recipientId", context.recipientId())
                + lengthPrefix("algorithm", context.algorithm().name())
                + lengthPrefix("ownerKeyId", context.ownerKeyId())
                + lengthPrefix("contentKeyVersion", Integer.toString(context.contentKeyVersion()))
                + lengthPrefix("policyHash", context.policyHash());
    }

    private static String lengthPrefix(String name, String value) {
        String safe = value == null ? "" : value;
        return name.length() + ":" + name + "=" + safe.length() + ":" + safe + ";";
    }
}
