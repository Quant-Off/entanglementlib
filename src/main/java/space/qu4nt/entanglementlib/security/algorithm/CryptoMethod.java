/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

/**
 * 암호화 방식을 정의하는 열거형 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public enum CryptoMethod {

    /**
     * KEM(Key Encapsulate Mechanism)
     */
    KEM,

    /**
     * 전자 서명 알고리즘
     */
    SIGN,

    /**
     * 대칭 키 암호화 알고리즘
     * <p>
     * 대용량 데이터 암호화에 적합한 알고리즘이며,
     * 암호화와 복호화에 동일한 키를 사용하는 알고리즘입니다.
     * <p>
     * 단, 암호화 키를 안전하게 공유해야 하는 것이 중요합니다.
     */
    SYMMETRIC,

    /**
     * 공개 키(비대칭) 암호화 알고리즘
     * <p>
     * 암호화할 때는 공개 키를 사용하고, 복호화할 때는 개인 키를 사용하는 알고리즘입니다.
     */
    ASYMMETRIC,

    /**
     * 스트림 암호화 알고리즘
     * <p>
     * 데이터를 비트(bit)나 바이트(byte) 단위로 연속적으로 암호화하는 알고리즘입니다.
     * 실시간 통신에 주로 사용됩니다.
     */
    STREAM,

    /**
     * 복합 알고리즘
     */
    COMPOSITE

}
