/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.language;

import org.junit.jupiter.api.*;

/**
 * 언어 출력을 테스트하는 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
class LanguageTest {

    @Test
    @DisplayName("다국어 로깅 테스트")
    void loggingTest() {
        System.out.println(Language.msg("class-SLHDSA.plaintext-or-byte-array-exc"));
        System.out.println(Language.msg(SupportedLanguage.en_US, "auth.class-Mode.not-support-aead"));
    }

}