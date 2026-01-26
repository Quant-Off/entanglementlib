/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto;

import lombok.Getter;

import java.util.Arrays;
import java.util.Objects;

import static space.qu4nt.entanglementlib.security.crypto.CryptoFamily.*;

/// 지원되는 전자 서명 알고리즘을 열거한 클래스입니다.
///
/// 이 열거형은 [EntLibAlgorithmType] 인터페이스를 구현하여 각 서명 알고리즘의
/// 패밀리, 키 크기, PQC(Post-Quantum Cryptography) 여부 등의 속성을 제공합니다.
///
/// @author Q. T. Felix
/// @see EntLibAlgorithmType
/// @see CryptoFamily
/// @since 1.1.0
@Getter
public enum SignatureType implements EntLibAlgorithmType {

    /**
     * ML-DSA-44 (NIST 보안 레벨 2) PQC 서명 알고리즘입니다.
     */
    ML_DSA_44(ML_DSA, ParameterSizeDetail.sign(
            0x520,
            0xa00,
            0x974), true),
    /**
     * ML-DSA-65 (NIST 보안 레벨 3) PQC 서명 알고리즘입니다.
     */
    ML_DSA_65(ML_DSA, ParameterSizeDetail.sign(
            0x7a0,
            0xfc0,
            0xced), true),
    /**
     * ML-DSA-87 (NIST 보안 레벨 5) PQC 서명 알고리즘입니다.
     */
    ML_DSA_87(ML_DSA, ParameterSizeDetail.sign(
            0xa20,
            0x1320,
            0x1213), true),

    //
    // SLH-DSA bundle - start
    //
    SLH_DSA_SHA2_128s(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHA2_128f(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHA2_192s(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHA2_192f(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHA2_256s(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHA2_256f(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHAKE_128s(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHAKE_128f(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHAKE_192s(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHAKE_192f(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHAKE_256s(SLH_DSA, ParameterSizeDetail.empty(), true),
    SLH_DSA_SHAKE_256f(SLH_DSA, ParameterSizeDetail.empty(), true),
    //
    // SLH-DSA bundle - end
    //

    /**
     * RSA 2048비트 키 서명 알고리즘입니다.
     */
    RSA_2048(RSA, ParameterSizeDetail.empty(), false),
    /**
     * RSA 4096비트 키 서명 알고리즘입니다.
     */
    RSA_4096(RSA, ParameterSizeDetail.empty(), false),
    ;

    /**
     * 서명 알고리즘 패밀리입니다.
     */
    private final CryptoFamily family;

    /**
     * 파라미터 디테일 객체입니다.
     */
    private final ParameterSizeDetail parameterSizeDetail;

    /**
     * PQC(Post-Quantum Cryptography) 알고리즘 여부입니다.
     */
    private final boolean pQC;

    private final String name = name();

    /**
     * {@link SignatureType} 열거형 생성자입니다.
     *
     * @param family  서명 알고리즘 패밀리
     * @param parameterSizeDetail 키 크기 (비트 단위)
     * @param pQC     PQC 알고리즘 여부
     */
    SignatureType(CryptoFamily family, ParameterSizeDetail parameterSizeDetail, boolean pQC) {
        this.family = family;
        this.parameterSizeDetail = parameterSizeDetail;
        this.pQC = pQC;
    }

    /**
     * 이 서명 알고리즘의 카테고리를 반환하는 메소드입니다.
     *
     * @return {@link EntLibCryptoCategory#SIGNATURE}
     */
    @Override
    public EntLibCryptoCategory getCategory() {
        return EntLibCryptoCategory.SIGNATURE;
    }

    public static SignatureType getByContextIdentifier(String identifier) {
        return Arrays.stream(SignatureType.values())
                .filter(type -> Objects.equals(type.getContextIdentifier(), identifier))
                .findFirst()
                .orElseThrow();
    }
}
