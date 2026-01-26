/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.crypto.key.EntLibCryptoKey;

/// 전자 서명을 수행하는 전략 인터페이스입니다.
///
/// ML-DSA, RSA 등의 전자 서명 알고리즘을 위한 전략을 정의합니다.
/// 서명 생성과 서명 검증 기능을 제공합니다.
///
/// @author Q. T. Felix
/// @see EntLibCryptoStrategy
/// @since 1.1.0
public interface SignatureStrategy extends EntLibCryptoStrategy {

    /**
     * 개인 키를 사용하여 데이터에 서명하는 메소드입니다.
     *
     * @param keyPrivate 서명에 사용할 개인 키
     * @param plainBytes 서명할 원본 데이터
     * @return 생성된 서명 바이트 배열
     */
    byte @NotNull [] sign(@NotNull EntLibCryptoKey keyPrivate, byte[] plainBytes);

    /**
     * 공개 키를 사용하여 서명을 검증하는 메소드입니다.
     *
     * @param keyPublic  검증에 사용할 공개 키
     * @param plainBytes 원본 데이터
     * @param signature  검증할 서명
     * @return 서명이 유효하면 {@code true}, 아니면 {@code false}
     */
    boolean verify(@NotNull EntLibCryptoKey keyPublic, byte[] plainBytes, byte[] signature);

}
