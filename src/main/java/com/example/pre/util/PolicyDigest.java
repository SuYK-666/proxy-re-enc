package com.example.pre.util;

import com.example.pre.crypto.hash.Hash;
import com.example.pre.model.AccessPolicy;

public final class PolicyDigest {
    private PolicyDigest() {
    }

    public static String sha256(AccessPolicy policy) {
        return Hash.sha256Hex(policy.canonicalJson());
    }
}
