/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoKEMProcessingException;

/// 네이티브 라이브러리를 사용하여 디피-헬만 키 교환(ECDH)를 수행하는 전략 인터페이스입니다.
/// 공유 비밀 계산 기능을 제공합니다.
///
/// @author Q. T. Felix
/// @see EntLibCryptoStrategy
/// @see SensitiveDataContainer
/// @since 1.1.0
public interface NativeECDHStrategy extends EntLibCryptoStrategy {

    SensitiveDataContainer computeSharedSecret(SensitiveDataContainer secretKeyContainer, SensitiveDataContainer peerPublicKeyContainer);
}
