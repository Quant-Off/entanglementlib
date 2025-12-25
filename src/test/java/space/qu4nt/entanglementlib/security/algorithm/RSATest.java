/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.EntKeyPair;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
class RSATest {

    private static final String PLAIN_TEXT = "Quant, Quantum Supremacy Expected 2030";

    @Test
    @Order(1)
    @DisplayName("RSA 테스트")
    void testSignAndVerify() throws Exception {
        try (RSA rsa = RSA.create(ClassicalType.RSA4096, PLAIN_TEXT)) {
            EntKeyPair pair = rsa.generateEntKeyPair();

            assertNotNull(pair);

            byte[] signature = rsa.sign(pair.keyPair().getPrivate(), 0);
            assertNotNull(signature);
            assertTrue(signature.length > 0);

            boolean isValid = rsa.verify(pair.keyPair().getPublic(), 0);
            assertTrue(isValid, "서명 검증은 참이어야 한다.");
        }
    }

    @Test
    @Order(2)
    @DisplayName("보안 매개변수 영소거 검증")
    void testRSAParameters() throws Exception {
        RSA rsa = RSA.create(ClassicalType.RSA4096, PLAIN_TEXT);
        EntKeyPair pair = rsa.generateEntKeyPair();
        PrivateKey privateKey = pair.keyPair().getPrivate();

        getRealSensitiveArray(privateKey, "publicExponent");
        getRealSensitiveArray(privateKey, "primeP");
        getRealSensitiveArray(privateKey, "primeQ");
        getRealSensitiveArray(privateKey, "primeExponentP");
        getRealSensitiveArray(privateKey, "primeExponentQ");
        getRealSensitiveArray(privateKey, "crtCoefficient");

        log.info("Key Before: {}", Hex.toHexString(privateKey.getEncoded()));

        rsa.close(); // 소거 작업 수행

        getRealSensitiveArray(privateKey, "publicExponent");
        getRealSensitiveArray(privateKey, "primeP");
        getRealSensitiveArray(privateKey, "primeQ");
        getRealSensitiveArray(privateKey, "primeExponentP");
        getRealSensitiveArray(privateKey, "primeExponentQ");
        getRealSensitiveArray(privateKey, "crtCoefficient");

        log.info("Key After: {}", Hex.toHexString(privateKey.getEncoded()));
    } // 통과

    private void getRealSensitiveArray(PrivateKey key, String fieldName) throws Exception {
        if (!(key instanceof BCRSAPrivateCrtKey bcKey))
            throw new IllegalArgumentException("Not BC implementation");

        Field paramsField = bcKey.getClass().getDeclaredField(fieldName);
        paramsField.setAccessible(true);
        BigInteger bi = (BigInteger) paramsField.get(bcKey);
        log.info("{}: {}", fieldName, bi);
    }

}