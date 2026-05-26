package com.example.pre.model;

import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.hash.Hash;
import com.example.pre.util.Bytes;

import java.nio.charset.StandardCharsets;

public record PackageManifest(
        String ciphertextHash,
        String aadHash,
        String capsuleHash,
        String policyHash,
        String grantContextHash,
        String chunkMerkleRoot,
        String manifestHash
) {
    public static PackageManifest issue(ReEncryptedPackage dataPackage) {
        return issue(dataPackage, "");
    }

    public static PackageManifest issue(ReEncryptedPackage dataPackage, String chunkMerkleRoot) {
        String ciphertextHash = Hash.sha256Hex(dataPackage.encryptedContent());
        String aadHash = Hash.sha256Hex(dataPackage.aad());
        String capsuleHash = capsuleHash(dataPackage.reEncryptedCapsule());
        String policyHash = dataPackage.grantPolicyHash();
        String root = chunkMerkleRoot == null ? "" : chunkMerkleRoot;
        String manifestHash = calculate(ciphertextHash, aadHash, capsuleHash, policyHash,
                dataPackage.grantContextHash(), root);
        return new PackageManifest(ciphertextHash, aadHash, capsuleHash, policyHash,
                dataPackage.grantContextHash(), root, manifestHash);
    }

    public boolean validates(ReEncryptedPackage dataPackage) {
        return equals(issue(dataPackage, chunkMerkleRoot));
    }

    private static String calculate(String ciphertextHash, String aadHash, String capsuleHash,
                                    String policyHash, String grantContextHash, String root) {
        return Hash.sha256Hex(String.join("|", "ReKeyShare-PackageManifest-v2", ciphertextHash,
                aadHash, capsuleHash, policyHash, grantContextHash, root)
                .getBytes(StandardCharsets.UTF_8));
    }

    private static String capsuleHash(EncryptedKeyCapsule capsule) {
        byte[] metadata = Bytes.utf8(String.join("|", capsule.capsuleId(), capsule.algorithm().name(),
                capsule.parameterSpec(), capsule.ownerKeyId(), Integer.toString(capsule.ownerKeyVersion()),
                capsule.aadHash(), capsule.contextHash()));
        return Hash.sha256Hex(Bytes.concat(metadata, capsule.header(), capsule.wrappedKey(), capsule.keyNonce()));
    }
}
