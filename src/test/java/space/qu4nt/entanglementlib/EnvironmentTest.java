/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import com.quant.quantregular.annotations.QuantCredential;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 내부연산테스트
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@QuantCredential(
        user = "Q. T. Felix",
        reason = "환경변수 호출 테스트를 제외하고 모든 테스트는 내부 유출 가능성 있어 숨김."
)
class EnvironmentTest {

    @Test
    @DisplayName("환경변수 호출 테스트")
    void envCallerTest() {
        assertAll("all",
                () -> assertNotNull(InternalFactory.envEntanglementHomeDir(), "null이면 안됌"),
                () -> assertNotNull(InternalFactory.envEntanglementPublicDir(), "null이면 안됌"),
                () -> System.out.println(InternalFactory.envEntanglementHomeDir()),
                () -> System.out.println(InternalFactory.envEntanglementPublicDir()));
    }

    // INTERNAL ----
}