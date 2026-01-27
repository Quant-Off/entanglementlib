/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.ProgressResult;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.critical.EntLibNativeError;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.ParameterSizeDetail;
import space.qu4nt.entanglementlib.security.crypto.bundle.MLKEMStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLDSAStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLKEMStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

/// ML-KEM(Module Lattice-based Key Encapsulate Mechanism) 알고리즘을 위한 비대칭 키 페어 생성 전략 클래스입니다.
///
/// ML-KEM는 NIST에서 표준화한 PQC(Post-Quantum Cryptography) 키 캡슐화 메커니즘으로,
/// ML-KEM 파라미터 세트를 지원합니다. [MLDSAStrategy]와 함께 사용됩니다.
///
/// 해당 알고리즘에 대한 암호학적 연산은 `entlib-native` 네이티브 라이브러리에서 진행됩니다.
///
/// @author Q. T. Felix
/// @see EntLibAsymmetricKeyStrategy
/// @see MLKEMStrategy
/// @since 1.1.0
@Slf4j
public final class MLKEMKeyStrategy implements EntLibAsymmetricKeyStrategy {

    private final KEMType mlkemType;

    private MLKEMKeyStrategy(KEMType mlkemType) {
        this.mlkemType = mlkemType;
    }

    public static MLKEMKeyStrategy create(@NotNull KEMType mlkemType) {
        return new MLKEMKeyStrategy(mlkemType);
    }

    @Override
    public Pair<SensitiveDataContainer, SensitiveDataContainer> generateKeyPair() throws Throwable {
        ParameterSizeDetail detail = mlkemType.getParameterSizeDetail();
        final SensitiveDataContainer pkC = new SensitiveDataContainer(detail.getEncapsulationKeySize());
        final SensitiveDataContainer skC = new SensitiveDataContainer(detail.getDecapsulationKeySize());
        int code = (int) MLKEMStrategyBundle
                .callNativeMLKEMHandle(mlkemType, 0)
                .invokeExact(skC.getMemorySegment(), pkC.getMemorySegment());
        final ProgressResult result = ProgressResult.fromCode(code);
        if (!result.equals(ProgressResult.SUCCESS))
            throw new EntLibNativeError("네이티브 함수 수행 결과가 유효하지 않습니다!");
        return new Pair<>(pkC, skC);
    }
}
