/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoKEMProcessingException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoSignatureProcessingException;

/// 네이티브 라이브러리를 사용하여 KEM을 수행하는 전략 인터페이스입니다.
/// 캡슐화 및 디캡슐화 기능을 제공합니다.
///
/// @author Q. T. Felix
/// @see EntLibCryptoStrategy
/// @see SensitiveDataContainer
/// @since 1.1.0
public interface NativeKEMStrategy extends EntLibCryptoStrategy {

    /// 공개 키를 사용하여 공유 비밀과 암호문을 생성하는 메소드입니다.
    ///
    /// 공개 키 매개변수 [SensitiveDataContainer] 객체는 컨테이너 내에 비밀 키
    /// 컨테이너가 포함되어 `있지 않다고` 예상합니다.
    ///
    /// @param keyPublic 캡슐화에 사용할 공개 키에 대한 `단일` 민감 데이터 컨테이너
    /// @return 생성된 공유 비밀과 암호문에 대한 민감 데이터 컨테이너
    SensitiveDataContainer encapsulate(@NotNull SensitiveDataContainer keyPublic) throws EntLibCryptoKEMProcessingException, EntLibSecureIllegalStateException;

    /// 비밀 키와 수신한 암호문을 사용하여 공유 비밀을 복원하는 메소드입니다.
    ///
    /// 비밀 키 매개변수 [SensitiveDataContainer] 객체는 컨테이너 내에 공개 키
    /// 컨테이너가 포함되어 `있지 않다고` 예상합니다. 이 과정에 비밀 키 메모리
    /// 세그먼트를 전달하면 공격자에게 탈취당할 위험이 있습니다.
    ///
    /// @param secretKeyContainer 비밀 키에 대한 민감 데이터 컨테이너
    /// @param ciphertext         수신한 암호문에 대한 민감 데이터 컨테이너
    /// @return 복원한 공유 비밀에 대한 민감 데이터 컨테이너
    SensitiveDataContainer decapsulate(@NotNull SensitiveDataContainer secretKeyContainer, @NotNull SensitiveDataContainer ciphertext) throws EntLibCryptoKEMProcessingException, EntLibSecureIllegalStateException;

}
