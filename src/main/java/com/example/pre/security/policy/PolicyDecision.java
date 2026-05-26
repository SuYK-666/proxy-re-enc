package com.example.pre.security.policy;

public record PolicyDecision(boolean allowed, String policyHash, String reasonCode) {
    public static PolicyDecision permit(String policyHash) {
        return new PolicyDecision(true, policyHash, "PERMIT");
    }

    public static PolicyDecision deny(String policyHash, String reasonCode) {
        return new PolicyDecision(false, policyHash, reasonCode);
    }
}
