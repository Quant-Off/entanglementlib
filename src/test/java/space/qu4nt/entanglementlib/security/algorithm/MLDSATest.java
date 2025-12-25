/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.EntKeyPair;

import java.lang.reflect.Field;
import java.security.PrivateKey;

import static org.junit.jupiter.api.Assertions.*;

class MLDSATest {

    private static final String PLAIN_TEXT = "Quant, Quantum Supremacy Expected 2030";

    @Test
    @Order(1)
    @DisplayName("ML-DSA 서명 및 검증 프로세스 정합성 테스트")
    void testSignAndVerify() throws Exception {
        try (MLDSA mldsa = MLDSA.create(MLDSAType.ML_DSA_65_WITH_SHA512, PLAIN_TEXT)) {
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
    void testMLDSAParameters() throws Exception {
        MLDSA mldsa = MLDSA.create(MLDSAType.ML_DSA_65_WITH_SHA512, PLAIN_TEXT);
        EntKeyPair pair = mldsa.generateEntKeyPair();
        PrivateKey privateKey = pair.keyPair().getPrivate();

        byte[] rho = getRealSensitiveArray(privateKey, "rho");
        byte[] k = getRealSensitiveArray(privateKey, "k");
        byte[] tr = getRealSensitiveArray(privateKey, "tr");
        byte[] s1 = getRealSensitiveArray(privateKey, "s1");
        byte[] s2 = getRealSensitiveArray(privateKey, "s2");
        byte[] t0 = getRealSensitiveArray(privateKey, "t0");
        byte[] t1 = getRealSensitiveArray(privateKey, "t1");
        byte[] seed = getRealSensitiveArray(privateKey, "seed");

        assertFalse(isZeroFilled(rho), "미리 영소거되지 않은 이상 이 오류를 볼 수 없을 겁니다.");
        assertFalse(isZeroFilled(k), "미리 영소거되지 않은 이상 이 오류를 볼 수 없을 겁니다.");
        assertFalse(isZeroFilled(tr), "미리 영소거되지 않은 이상 이 오류를 볼 수 없을 겁니다.");
        assertFalse(isZeroFilled(s1), "미리 영소거되지 않은 이상 이 오류를 볼 수 없을 겁니다.");
        assertFalse(isZeroFilled(s2), "미리 영소거되지 않은 이상 이 오류를 볼 수 없을 겁니다.");
        assertFalse(isZeroFilled(t0), "미리 영소거되지 않은 이상 이 오류를 볼 수 없을 겁니다.");
        assertFalse(isZeroFilled(t1), "미리 영소거되지 않은 이상 이 오류를 볼 수 없을 겁니다.");
        assertFalse(isZeroFilled(seed), "미리 영소거되지 않은 이상 이 오류를 볼 수 없을 겁니다.");

        mldsa.close(); // 소거 작업 수행

        assertAll("ML-DSA 실제 민감 필드 영소거 검증",
                () -> assertTrue(isZeroFilled(rho), "rho 는 영소거되어야 합니다."),
                () -> assertTrue(isZeroFilled(k), "k 는 영소거되어야 합니다."),
                () -> assertTrue(isZeroFilled(tr), "tr 는 영소거되어야 합니다."),
                () -> assertTrue(isZeroFilled(s1), "s1 는 영소거되어야 합니다."),
                () -> assertTrue(isZeroFilled(s2), "s2 는 영소거되어야 합니다."),
                () -> assertTrue(isZeroFilled(t0), "t0 는 영소거되어야 합니다."),
                () -> assertTrue(isZeroFilled(t1), "t1 는 영소거되어야 합니다."),
                () -> assertTrue(isZeroFilled(seed), "seed 는 영소거되어야 합니다.")
        );
    } // 통과

    private byte[] getRealSensitiveArray(PrivateKey key, String fieldName) throws Exception {
        if (!(key instanceof BCMLDSAPrivateKey bcKey))
            throw new IllegalArgumentException("Not BC implementation");

        Field paramsField = bcKey.getClass().getDeclaredField("params");
        paramsField.setAccessible(true);
        MLDSAPrivateKeyParameters params = (MLDSAPrivateKeyParameters) paramsField.get(bcKey);

        Field f = params.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return (byte[]) f.get(params);
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