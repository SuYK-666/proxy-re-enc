package com.example.pre.crypto;

import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.model.UserKeyPair;
import com.example.pre.util.SecureRandomUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class PreSchemeNegativeTest {
    @Test
    void rsaSchemeRejectsEccCapsule() {
        RsaPreScheme rsa = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        EccPreScheme ecc = new EccPreScheme();
        UserKeyPair eccAlice = ecc.generateKeyPair("alice");
        EncryptedKeyCapsule eccCapsule = ecc.encapsulate(SecureRandomUtil.randomBytes(32), eccAlice.publicKey());
        UserKeyPair rsaAlice = rsa.generateKeyPair("rsa-alice");
        assertThrows(IllegalArgumentException.class, () -> rsa.decapsulate(eccCapsule, rsaAlice.privateKey()));
    }

    @Test
    void eccSchemeRejectsRsaCapsule() {
        RsaPreScheme rsa = new RsaPreScheme(RsaCommonModulusParameters.generate(1024));
        EccPreScheme ecc = new EccPreScheme();
        UserKeyPair rsaAlice = rsa.generateKeyPair("alice");
        EncryptedKeyCapsule rsaCapsule = rsa.encapsulate(SecureRandomUtil.randomBytes(32), rsaAlice.publicKey());
        UserKeyPair eccAlice = ecc.generateKeyPair("ecc-alice");
        assertThrows(IllegalArgumentException.class, () -> ecc.decapsulate(rsaCapsule, eccAlice.privateKey()));
    }
}
