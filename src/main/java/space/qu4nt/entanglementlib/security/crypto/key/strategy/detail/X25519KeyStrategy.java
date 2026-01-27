/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import space.qu4nt.entanglementlib.entlibnative.ProgressResult;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.critical.EntLibNativeError;
import space.qu4nt.entanglementlib.security.crypto.bundle.X25519StrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.X25519Strategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

/// X25519 알고리즘을 위한 비대칭 키 페어 생성 전략 클래스입니다.
///
/// X25519는 `Curve25519` 타원 곡선을 사용한 고보안 `ECDH` 키 교환 알고리즘입니다.
///
/// 해당 알고리즘에 대한 암호학적 연산은 `entlib-native` 네이티브 라이브러리에서 진행됩니다.
///
/// @author Q. T. Felix
/// @see EntLibAsymmetricKeyStrategy
/// @see X25519Strategy
/// @since 1.1.0
@Slf4j
public final class X25519KeyStrategy implements EntLibAsymmetricKeyStrategy {

    private X25519KeyStrategy() {
    }

    public static X25519KeyStrategy create() {
        return new X25519KeyStrategy();
    }

    @Override
    public Pair<SensitiveDataContainer, SensitiveDataContainer> generateKeyPair() throws Throwable {
        final Pair<Integer, Integer> keySizePair = new Pair<>(0x20, 0x20);
        final SensitiveDataContainer pkC = new SensitiveDataContainer(keySizePair.getFirst());
        final SensitiveDataContainer skC = new SensitiveDataContainer(keySizePair.getSecond());
        int code = (int) X25519StrategyBundle
                .callNativeX25519Handle(0)
                .invokeExact(skC.getMemorySegment(), pkC.getMemorySegment());
        final ProgressResult result = ProgressResult.fromCode(code);
        if (!result.equals(ProgressResult.SUCCESS))
            throw new EntLibNativeError("네이티브 함수 수행 결과가 유효하지 않습니다!");
        return new Pair<>(pkC, skC);
    }
}
