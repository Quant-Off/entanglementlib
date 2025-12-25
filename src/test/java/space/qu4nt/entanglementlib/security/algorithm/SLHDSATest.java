/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPrivateKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.EntKeyPair;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SLHDSATest {

    private static final String PLAIN_TEXT = "Quant, Quantum Supremacy Expected 2030";

    @Test
    @Order(1)
    @DisplayName("SLH-DSA 서명 및 검증 프로세스 정합성 테스트")
    void testSignAndVerify() throws Exception {
        try (SLHDSA mldsa = SLHDSA.create(SLHDSAType.SLH_DSA_SHAKE_256s_WITH_SHAKE256, PLAIN_TEXT)) {
            EntKeyPair pair = mldsa.generateEntKeyPair();
            assertNotNull(pair);

            byte[] signature = mldsa.sign(pair.keyPair().getPrivate(), 0);
            assertNotNull(signature);
            assertTrue(signature.length > 0);

            boolean isValid = mldsa.verify(pair.keyPair().getPublic(), 0);
            assertTrue(isValid, "서명 검증은 참이어야 한다.");
        }
    }

    @Test
    @Order(2)
    @DisplayName("보안 매개변수 영소거 검증")
    void testSLHDSAParameters() throws Exception {
        SLHDSA slhdsa = SLHDSA.create(SLHDSAType.SLH_DSA_SHAKE_256s_WITH_SHAKE256, PLAIN_TEXT);
        EntKeyPair pair = slhdsa.generateEntKeyPair();
        PrivateKey privateKey = pair.keyPair().getPrivate();

        List<byte[]> list = getRealSensitiveArray(privateKey);
        slhdsa.close(); // 소거 작업 수행

        list.forEach(v -> assertTrue(isZeroFilled(v), "영소거 되지 않은 값이 있습니다. 확인해보세요."));
    } // 통과

    private List<byte[]> getRealSensitiveArray(PrivateKey key) throws Exception {
        if (!(key instanceof BCSLHDSAPrivateKey bcKey))
            throw new IllegalArgumentException("Not BC implementation");
        List<byte[]> list = new ArrayList<>();

        Field paramsField = bcKey.getClass().getDeclaredField("params");
        paramsField.setAccessible(true);
        String[] classes = {"org.bouncycastle.pqc.crypto.slhdsa.SK", "org.bouncycastle.pqc.crypto.slhdsa.PK"};
        for (String classPath : classes) {
            Class<?> clazz = Class.forName(classPath);
            Constructor<?> constr = clazz.getDeclaredConstructor(byte[].class, byte[].class);
            constr.setAccessible(true);
            byte[] empty = new byte[0];
            Object instance = constr.newInstance(empty, empty);
            for (Field f : clazz.getDeclaredFields()) {
                f.setAccessible(true);
                byte[] arr = (byte[]) f.get(instance);
                list.add(arr);
            }
        }
        return list;
    }

    // 바이트 배열이 모두 0인지 확인하는 메소드입니다
    private static boolean isZeroFilled(byte[] array) {
        if (array == null) return true;
        for (byte b : array) {
            if (b != 0) return false;
        }
        return true;
    }
}