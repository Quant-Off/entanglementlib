/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoSignatureProcessingException;

/// 네이티브 라이브러리를 사용하여 전자 서명을 수행하는 전략 인터페이스입니다.
/// 서명 생성과 서명 검증 기능을 제공합니다.
///
/// @author Q. T. Felix
/// @see EntLibCryptoStrategy
/// @see SensitiveDataContainer
/// @since 1.1.0
public interface NativeSignatureStrategy extends EntLibCryptoStrategy {

    /// 개인 키를 사용하여 데이터에 서명하는 메소드입니다.
    ///
    /// 비밀 키 매개변수 [SensitiveDataContainer] 객체는 컨테이너 내에 공개 키
    /// 컨테이너가 포함되어 `있지 않다고` 예상합니다. 이 부분에 대해 내부적으로는 크게
    /// 신경쓰지 않지만, 보안 상 이 부분을 명확히 할 필요가 있습니다.
    ///
    /// 서명이 완료되면 컨테이너에 공개 키를 추가하여 사용자에게 전송하도록 설계할 수
    /// 있습니다.
    ///
    /// @param keyPrivate 서명에 사용할 개인 키에 대한 `단일` 민감 데이터 컨테이너
    /// @param plainBytes 서명할 원본 데이터
    /// @return 생성된 서명 바이트 배열과 평문에 대한 민감 데이터 컨테이너
    SensitiveDataContainer sign(@NotNull SensitiveDataContainer keyPrivate, byte[] plainBytes) throws EntLibCryptoSignatureProcessingException;

    /// 공개 키를 사용하여 서명을 검증하는 메소드입니다.
    ///
    /// 공개 키 매개변수 [SensitiveDataContainer] 객체는 컨테이너 내에 비밀 키
    /// 컨테이너가 포함되어 `있지 않다고` 예상합니다. 이 과정에 비밀 키 메모리
    /// 세그먼트를 전달하면 공격자에게 탈취당할 위험이 있습니다.
    ///
    /// @param container  생성된 서명 바이트 배열과 평문, 공개 키에 대한 민감 데이터 컨테이너
    /// @return 서명이 유효하면 `true`, 아니면 `false`
    boolean verify(@NotNull SensitiveDataContainer container) throws EntLibCryptoSignatureProcessingException;

}
