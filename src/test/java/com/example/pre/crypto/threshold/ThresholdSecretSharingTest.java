package com.example.pre.crypto.threshold;

import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ThresholdSecretSharingTest {
    @Test
    void twoOfThreeReconstructsAndOneShareCannot() {
        byte[] secret = SecureRandomUtil.randomBytes(32);
        var shares = ThresholdSecretSharing.split(secret, 2, 3);
        assertThrows(IllegalArgumentException.class, () -> ThresholdSecretSharing.combine(shares.subList(0, 1)));
        assertArrayEquals(secret, ThresholdSecretSharing.combine(shares.subList(0, 2)));
        assertArrayEquals(secret, ThresholdSecretSharing.combine(shares));
    }

    @Test
    void threeOfFiveReconstructsAndTwoSharesCannot() {
        byte[] secret = SecureRandomUtil.randomBytes(32);
        var shares = ThresholdSecretSharing.split(secret, 3, 5);
        assertThrows(IllegalArgumentException.class, () -> ThresholdSecretSharing.combine(shares.subList(0, 2)));
        assertArrayEquals(secret, ThresholdSecretSharing.combine(shares.subList(0, 3)));
        assertArrayEquals(secret, ThresholdSecretSharing.combine(shares.subList(1, 5)));
    }
}
