package com.example.pre.benchmark;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class ReproducibleDatasetTest {
    @Test
    void providesFiveDistinctRepeatableDistributions() {
        assertEquals(5, ReproducibleDataset.distributions().size());
        for (String distribution : ReproducibleDataset.distributions()) {
            byte[] first = ReproducibleDataset.generate(distribution, 4096, 7);
            byte[] replay = ReproducibleDataset.generate(distribution, 4096, 7);
            byte[] otherRound = ReproducibleDataset.generate(distribution, 4096, 8);
            assertEquals(Arrays.toString(first), Arrays.toString(replay));
            if (!"compressible".equals(distribution)) {
                assertFalse(Arrays.equals(first, otherRound));
            }
        }
    }
}
