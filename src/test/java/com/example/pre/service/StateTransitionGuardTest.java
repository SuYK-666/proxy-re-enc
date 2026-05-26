package com.example.pre.service;

import com.example.pre.model.DataStatus;
import com.example.pre.model.GrantStatus;
import com.example.pre.model.KeyStatus;
import com.example.pre.model.PackageStatus;
import com.example.pre.model.ProxyNodeStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StateTransitionGuardTest {
    @Test
    void acceptsLifecycleTransitionsAndRejectsTerminalReuse() {
        StateTransitionGuard guard = new StateTransitionGuard();
        assertDoesNotThrow(() -> guard.grant(GrantStatus.ACTIVE, GrantStatus.REVOKED));
        assertDoesNotThrow(() -> guard.dataPackage(PackageStatus.ACTIVE, PackageStatus.INVALIDATED));
        ReKeyShareException invalid = assertThrows(ReKeyShareException.class,
                () -> guard.grant(GrantStatus.REVOKED, GrantStatus.ACTIVE));
        assertEquals(ErrorCode.INVALID_STATE_TRANSITION, invalid.code());
    }

    @Test
    void exhaustivelyChecksEveryAggregateTransitionTable() {
        StateTransitionGuard guard = new StateTransitionGuard();
        for (DataStatus from : DataStatus.values()) {
            for (DataStatus to : DataStatus.values()) {
                boolean allowed = from == DataStatus.ACTIVE && (to == DataStatus.ROTATING || to == DataStatus.REVOKED || to == DataStatus.DELETED)
                        || from == DataStatus.ROTATING && (to == DataStatus.ACTIVE || to == DataStatus.REVOKED);
                assertTransition(allowed, () -> guard.data(from, to));
            }
        }
        for (GrantStatus from : GrantStatus.values()) {
            for (GrantStatus to : GrantStatus.values()) {
                boolean allowed = from == GrantStatus.CREATED && to == GrantStatus.ACTIVE
                        || from == GrantStatus.ACTIVE && (to == GrantStatus.EXPIRED || to == GrantStatus.REVOKED || to == GrantStatus.ROTATED);
                assertTransition(allowed, () -> guard.grant(from, to));
            }
        }
        for (PackageStatus from : PackageStatus.values()) {
            for (PackageStatus to : PackageStatus.values()) {
                boolean allowed = from == PackageStatus.ACTIVE && (to == PackageStatus.EXPIRED
                        || to == PackageStatus.INVALIDATED || to == PackageStatus.ROTATED);
                assertTransition(allowed, () -> guard.dataPackage(from, to));
            }
        }
        for (ProxyNodeStatus from : ProxyNodeStatus.values()) {
            for (ProxyNodeStatus to : ProxyNodeStatus.values()) {
                boolean allowed = from == ProxyNodeStatus.ACTIVE && (to == ProxyNodeStatus.DISABLED || to == ProxyNodeStatus.REVOKED)
                        || from == ProxyNodeStatus.DISABLED && (to == ProxyNodeStatus.ACTIVE || to == ProxyNodeStatus.REVOKED);
                assertTransition(allowed, () -> guard.proxy(from, to));
            }
        }
        for (KeyStatus from : KeyStatus.values()) {
            for (KeyStatus to : KeyStatus.values()) {
                boolean allowed = from == KeyStatus.ACTIVE && (to == KeyStatus.ROTATED || to == KeyStatus.REVOKED)
                        || from == KeyStatus.ROTATED && to == KeyStatus.REVOKED;
                assertTransition(allowed, () -> guard.key(from, to));
            }
        }
    }

    private static void assertTransition(boolean allowed, org.junit.jupiter.api.function.Executable transition) {
        if (allowed) {
            assertDoesNotThrow(transition);
        } else {
            assertEquals(ErrorCode.INVALID_STATE_TRANSITION,
                    assertThrows(ReKeyShareException.class, transition).code());
        }
    }
}
