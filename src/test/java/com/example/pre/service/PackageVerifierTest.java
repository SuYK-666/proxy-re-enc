package com.example.pre.service;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.provider.SchemeDescriptor;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.PackageManifest;
import com.example.pre.model.SharedPackageV2;
import com.example.pre.util.Bytes;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PackageVerifierTest {
    private final SchemeDescriptor descriptor = new SchemeDescriptor("RSA_PRE_BASELINE", "RSA", "EXPERIMENTAL",
            "test", true, true, false, "NOT_PRODUCTION_REVIEWED", "IMPLEMENTED");

    @Test
    void validatesIssuedV2PackageAndRejectsCiphertextTamper() {
        ReEncryptedPackage original = fixture(Bytes.utf8("ciphertext"));
        original = original.withIssuedManifestHash(PackageManifest.issue(original).manifestHash());
        SharedPackageV2 issued = SharedPackageV2.issue(original, descriptor, Instant.now().plusSeconds(30));
        PackageVerifier verifier = new PackageVerifier();
        assertDoesNotThrow(() -> verifier.verify(issued, Instant.now()));

        SharedPackageV2 tampered = new SharedPackageV2(issued.packageVersion(), issued.schemeId(),
                issued.parameterSpec(), issued.proofStatus(), issued.keyVersion(), issued.expiresAt(),
                fixture(Bytes.utf8("changed-ciphertext")), issued.manifest());
        ReKeyShareException failure = assertThrows(ReKeyShareException.class,
                () -> verifier.verify(tampered, Instant.now()));
        assertEquals(ErrorCode.PACKAGE_INVALID, failure.code());
    }

    @Test
    void rejectsExpiredV2Package() {
        SharedPackageV2 expired = SharedPackageV2.issue(fixture(Bytes.utf8("ciphertext")), descriptor,
                Instant.now().minusSeconds(1));
        assertEquals(ErrorCode.PACKAGE_EXPIRED,
                assertThrows(ReKeyShareException.class,
                        () -> new PackageVerifier().verify(expired, Instant.now())).code());
    }

    @Test
    void rejectsUnknownPackageVersion() {
        SharedPackageV2 issued = SharedPackageV2.issue(fixture(Bytes.utf8("ciphertext")), descriptor,
                Instant.now().plusSeconds(30));
        SharedPackageV2 unknown = new SharedPackageV2("v99", issued.schemeId(), issued.parameterSpec(),
                issued.proofStatus(), issued.keyVersion(), issued.expiresAt(), issued.payload(), issued.manifest());
        assertEquals(ErrorCode.PACKAGE_INVALID,
                assertThrows(ReKeyShareException.class,
                        () -> new PackageVerifier().verify(unknown, Instant.now())).code());
    }

    private static ReEncryptedPackage fixture(byte[] ciphertext) {
        return new ReEncryptedPackage("data-1", "alice", "bob", AlgorithmType.RSA_PRE,
                ciphertext, Bytes.utf8("nonce-12byte"), Bytes.utf8("aad"),
                new EncryptedKeyCapsule(AlgorithmType.RSA_PRE, Bytes.utf8("header"),
                        Bytes.utf8("wrapped"), Bytes.utf8("keynonce-12b")), Instant.now());
    }
}
