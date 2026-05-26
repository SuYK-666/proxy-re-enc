package com.example.pre.security.policy;

import com.example.pre.crypto.hash.Hash;

public final class PolicyEvaluator {
    public PolicyDecision evaluate(PolicyExpression expression, PolicyRequest request) {
        String policyHash = Hash.sha256Hex(expression.canonical());
        if (!expression.tenantId().isBlank() && !expression.tenantId().equals(request.tenantId())) {
            return PolicyDecision.deny(policyHash, "TENANT_DENIED");
        }
        if (!expression.allowedRoles().isEmpty() && !expression.allowedRoles().contains(request.role())) {
            return PolicyDecision.deny(policyHash, "ROLE_DENIED");
        }
        if (!expression.allowedActions().contains(request.action())) {
            return PolicyDecision.deny(policyHash, "ACTION_DENIED");
        }
        if (!expression.requiredPurpose().isBlank() && !expression.requiredPurpose().equals(request.purpose())) {
            return PolicyDecision.deny(policyHash, "PURPOSE_DENIED");
        }
        if (!expression.requiredClassification().isBlank()
                && !expression.requiredClassification().equals(request.classification())) {
            return PolicyDecision.deny(policyHash, "CLASSIFICATION_DENIED");
        }
        if (expression.notBefore() != null && request.now().isBefore(expression.notBefore())) {
            return PolicyDecision.deny(policyHash, "NOT_YET_VALID");
        }
        if (expression.expiresAt() != null && !request.now().isBefore(expression.expiresAt())) {
            return PolicyDecision.deny(policyHash, "GRANT_EXPIRED");
        }
        if (request.consumedAccessCount() >= expression.maxAccessCount()) {
            return PolicyDecision.deny(policyHash, "ACCESS_LIMIT_EXCEEDED");
        }
        if (expression.requireActiveProxy() && !request.proxyActive()) {
            return PolicyDecision.deny(policyHash, "PROXY_INACTIVE");
        }
        return PolicyDecision.permit(policyHash);
    }
}
