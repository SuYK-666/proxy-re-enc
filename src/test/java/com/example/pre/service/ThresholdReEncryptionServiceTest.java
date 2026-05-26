package com.example.pre.service;

import com.example.pre.crypto.threshold.ThresholdReKeyShare;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ThresholdReEncryptionServiceTest {
    @Test
    void supportsTwoOfThreeAndThreeOfFiveConfigurations() {
        verifyConfiguration(2, List.of("proxy-a", "proxy-b", "proxy-c"));
        verifyConfiguration(3, List.of("proxy-a", "proxy-b", "proxy-c", "proxy-d", "proxy-e"));
    }

    @Test
    void rejectsInsufficientAndTamperedSignedShares() {
        ThresholdReEncryptionService service = new ThresholdReEncryptionService();
        byte[] secret = Bytes.utf8("experimental-rekey");
        List<ThresholdReKeyShare> shares = service.splitForProxies(secret, 2, List.of("proxy-a", "proxy-b", "proxy-c"));
        var onlyOne = service.convertShare("proxy-a", shares.get(0));
        ReKeyShareException insufficient = assertThrows(ReKeyShareException.class,
                () -> service.aggregate(List.of(onlyOne)));
        assertEquals(ErrorCode.THRESHOLD_NOT_REACHED, insufficient.code());

        ThresholdReKeyShare modified = new ThresholdReKeyShare(shares.get(1).threshold(), shares.get(1).totalShares(),
                shares.get(1).index(), Bytes.utf8("forged"));
        var signed = service.convertShare("proxy-b", shares.get(1));
        var tampered = new ThresholdReEncryptionService.SignedShare(signed.proxyId(), modified, signed.shareDigest(),
                signed.signatureAlgorithm(), signed.publicKey(), signed.signature());
        ReKeyShareException invalid = assertThrows(ReKeyShareException.class,
                () -> service.aggregate(List.of(onlyOne, tampered)));
        assertEquals(ErrorCode.THRESHOLD_SHARE_INVALID, invalid.code());
    }

    private static void verifyConfiguration(int threshold, List<String> proxies) {
        ThresholdReEncryptionService service = new ThresholdReEncryptionService();
        byte[] secret = Bytes.utf8("rekey-" + threshold + "-" + proxies.size());
        List<ThresholdReKeyShare> shares = service.splitForProxies(secret, threshold, proxies);
        List<ThresholdReEncryptionService.SignedShare> submitted = new ArrayList<>();
        for (int index = 0; index < threshold; index++) {
            submitted.add(service.convertShare(proxies.get(index), shares.get(index)));
        }
        assertArrayEquals(secret, service.aggregate(submitted));
    }
}
