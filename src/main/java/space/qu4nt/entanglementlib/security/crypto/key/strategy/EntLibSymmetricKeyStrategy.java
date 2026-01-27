/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy;

import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.crypto.key.EntLibKey;

/// 네이티브에서 수행되는 대칭 키 생성 전략을 정의하는 인터페이스입니다.
///
/// AES, ARIA, ChaCha20 등의 대칭 키 암호화 알고리즘에 사용되는 비밀 키를 생성합니다.
/// 각 알고리즘별 구현체가 이 인터페이스를 구현하여 해당 알고리즘에 적합한 키를 생성합니다.
///
/// @author Q. T. Felix
/// @see SensitiveDataContainer
/// @see EntLibAsymmetricKeyStrategy 비대칭 키 생성 전략 인터페이스
/// @since 1.1.0
public interface EntLibSymmetricKeyStrategy extends EntLibKey {

    /// 대칭 키를 생성하여 반환하는 메소드입니다.
    ///
    /// 생성된 키는 [SensitiveDataContainer]로 래핑되어 네이티브 메모리에 안전하게 저장됩니다.
    /// `heap` 메모리에 잔류하는 키 바이트 배열은 즉시 소거됩니다.
    ///
    /// @return 생성된 대칭 키
    SensitiveDataContainer generateKey();

}
