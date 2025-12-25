/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.wrapper;

/**
 * {@code BouncyCastle} 라이브러리의 {@code Hex} 클래스의 몇 가지
 * 유틸리티를 바인딩(래핑)하기 위한 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public final class Hex {

    /**
     * {@code BouncyCastle} 라이브러리의 {@code Hex} 컨버팅
     * 도구를 바인딩(래핑)하기 위한 메소드입니다.
     *
     * @param bytes 바이트 배열
     * @return 바이트 배열의 Hex 문자열 표현
     */
    public static String toHexString(byte[] bytes) {
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

}
