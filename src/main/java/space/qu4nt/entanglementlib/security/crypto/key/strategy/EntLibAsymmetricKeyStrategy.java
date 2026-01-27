/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy;

import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.crypto.key.EntLibKey;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

/// 네이티브에서 수행되는 비대칭 키 페어 생성 전략을 정의하는 인터페이스입니다.
/// 각 알고리즘별 구현체가 이 인터페이스를 구현하여 해당 알고리즘에 적합한 키 페어를 생성합니다.
///
/// @author Q. T. Felix
/// @see SensitiveDataContainer
/// @see EntLibSymmetricKeyStrategy 대칭 키 생성 전략 인터페이스
/// @since 1.1.0
public interface EntLibAsymmetricKeyStrategy extends EntLibKey {

    /**
     * 비대칭 키 페어(공개 키, 개인 키)을 생성하여 반환하는 메소드입니다.
     * <p>
     * 반환되는 {@link Pair}의 첫 번째 요소는 공개 키, 두 번째 요소는 개인 키입니다.
     * 생성된 키 페어는 {@link SensitiveDataContainer}로 래핑되어 네이티브 메모리에
     * 안전하게 저장됩니다.
     *
     * @return 공개 키와 개인 키의 페어
     */
    Pair<SensitiveDataContainer, SensitiveDataContainer> generateKeyPair() throws Throwable;

}
