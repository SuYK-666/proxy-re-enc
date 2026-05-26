package com.example.pre.service;

import com.example.pre.model.DataStatus;
import com.example.pre.model.GrantStatus;
import com.example.pre.model.KeyStatus;
import com.example.pre.model.PackageStatus;
import com.example.pre.model.ProxyNodeStatus;

public final class StateTransitionGuard {
    public void data(DataStatus from, DataStatus to) {
        require(from == DataStatus.ACTIVE && (to == DataStatus.ROTATING || to == DataStatus.REVOKED || to == DataStatus.DELETED)
                || from == DataStatus.ROTATING && (to == DataStatus.ACTIVE || to == DataStatus.REVOKED),
                "data", from, to);
    }

    public void grant(GrantStatus from, GrantStatus to) {
        require((from == GrantStatus.CREATED && to == GrantStatus.ACTIVE)
                || (from == GrantStatus.ACTIVE && (to == GrantStatus.EXPIRED || to == GrantStatus.REVOKED || to == GrantStatus.ROTATED)),
                "grant", from, to);
    }

    public void dataPackage(PackageStatus from, PackageStatus to) {
        require(from == PackageStatus.ACTIVE && (to == PackageStatus.EXPIRED || to == PackageStatus.INVALIDATED || to == PackageStatus.ROTATED),
                "package", from, to);
    }

    public void proxy(ProxyNodeStatus from, ProxyNodeStatus to) {
        require(from == ProxyNodeStatus.ACTIVE && (to == ProxyNodeStatus.DISABLED || to == ProxyNodeStatus.REVOKED)
                || from == ProxyNodeStatus.DISABLED && (to == ProxyNodeStatus.ACTIVE || to == ProxyNodeStatus.REVOKED),
                "proxy", from, to);
    }

    public void key(KeyStatus from, KeyStatus to) {
        require(from == KeyStatus.ACTIVE && (to == KeyStatus.ROTATED || to == KeyStatus.REVOKED)
                || from == KeyStatus.ROTATED && to == KeyStatus.REVOKED, "key", from, to);
    }

    private static void require(boolean allowed, String aggregate, Enum<?> from, Enum<?> to) {
        if (!allowed) {
            throw new ReKeyShareException(ErrorCode.INVALID_STATE_TRANSITION,
                    "illegal " + aggregate + " transition: " + from + " -> " + to);
        }
    }
}
