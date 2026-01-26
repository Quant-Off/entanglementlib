/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto;

import lombok.Getter;

import java.util.Arrays;
import java.util.Objects;

import static space.qu4nt.entanglementlib.security.crypto.CryptoFamily.*;

/// 지원되는 KEM 알고리즘을 열거한 클래스입니다.
///
/// 이 열거형은 [EntLibAlgorithmType] 인터페이스를 구현하여 각 서명 알고리즘의
/// 패밀리, 키 크기, PQC(Post-Quantum Cryptography) 여부 등의 속성을 제공합니다.
///
/// @author Q. T. Felix
/// @see EntLibAlgorithmType
/// @see CryptoFamily
/// @since 1.1.0
@Getter
public enum KEMType implements EntLibAlgorithmType {

    /**
     * ML-KEM-512 PQC KEM 알고리즘입니다.
     */
    ML_KEM_512(ML_KEM, ParameterSizeDetail.kem(
            0x320,
            0x660,
            0x300,
            0x20), true),
    /**
     * ML-KEM-768 PQC KEM 알고리즘입니다.
     */
    ML_KEM_768(ML_KEM, ParameterSizeDetail.kem(
            0x4a0,
            0x960,
            0x440,
            0x20), true),
    /**
     * ML-KEM-1024(QC KEM 알고리즘입니다.
     */
    ML_KEM_1024(ML_KEM, ParameterSizeDetail.kem(
            0x620,
            0xc60,
            0x620,
            0x20), true),

    X25519(Curves, ParameterSizeDetail.kem(
            0x20,
            0x20,
            0x20,
            0x20), false),

    X25519MLKEM768(HYBRID, ParameterSizeDetail.kem(
            0x4a0 + 0x20,
            0x960 + 0x20,
            0x440 + 0x20,
            0x20 + 0x20
    ), true)
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
     * {@link KEMType} 열거형 생성자입니다.
     *
     * @param family  KEM 알고리즘 패밀리
     * @param parameterSizeDetail 키 크기 (비트 단위)
     * @param pQC     PQC 알고리즘 여부
     */
    KEMType(CryptoFamily family, ParameterSizeDetail parameterSizeDetail, boolean pQC) {
        this.family = family;
        this.parameterSizeDetail = parameterSizeDetail;
        this.pQC = pQC;
    }

    /**
     * 이 KEM 알고리즘의 카테고리를 반환하는 메소드입니다.
     *
     * @return {@link EntLibCryptoCategory#SIGNATURE}
     */
    @Override
    public EntLibCryptoCategory getCategory() {
        return EntLibCryptoCategory.KEM;
    }

    public static KEMType getByContextIdentifier(String identifier) {
        return Arrays.stream(KEMType.values())
                .filter(type -> Objects.equals(type.getContextIdentifier(), identifier))
                .findFirst()
                .orElseThrow();
    }
}
