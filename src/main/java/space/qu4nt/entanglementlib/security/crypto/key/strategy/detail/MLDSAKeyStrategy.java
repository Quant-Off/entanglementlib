/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.ProgressResult;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.critical.EntLibNativeError;
import space.qu4nt.entanglementlib.security.crypto.ParameterSizeDetail;
import space.qu4nt.entanglementlib.security.crypto.SignatureType;
import space.qu4nt.entanglementlib.security.crypto.bundle.MLDSAStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLDSAStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

/// ML-DSA(Module Lattice-based Digital Signature Algorithm) 알고리즘을 위한 비대칭 키 페어 생성 전략 클래스입니다.
///
/// ML-DSA는 NIST에서 표준화한 PQC(Post-Quantum Cryptography) 전자 서명 알고리즘으로,
/// ML-DSA 파라미터 세트를 지원합니다. [MLDSAStrategy]와 함께 사용됩니다.
///
/// 해당 알고리즘에 대한 암호학적 연산은 `entlib-native` 네이티브 라이브러리에서 진행됩니다.
///
/// @author Q. T. Felix
/// @see EntLibAsymmetricKeyStrategy
/// @see MLDSAStrategy
/// @since 1.1.0
@Slf4j
public final class MLDSAKeyStrategy implements EntLibAsymmetricKeyStrategy {

    private final SignatureType mldsaType;

    private MLDSAKeyStrategy(SignatureType mldsaType) {
        this.mldsaType = mldsaType;
    }

    @ApiStatus.Internal
    public static MLDSAKeyStrategy create(@NotNull SignatureType mldsaType) {
        return new MLDSAKeyStrategy(mldsaType);
    }

    @Override
    public Pair<SensitiveDataContainer, SensitiveDataContainer> generateKeyPair() throws Throwable {
        ParameterSizeDetail detail = mldsaType.getParameterSizeDetail();
        // 주의! 특정 키 내에 다른 키 컨테이너를 포함해선 안됨
        final SensitiveDataContainer pkC = new SensitiveDataContainer(detail.getPublicKeySize());
        final SensitiveDataContainer skC = new SensitiveDataContainer(detail.getPrivateKeySize());
        // ml_dsa_xx_keygen(sk_ptr, pk_ptr) - sk가 먼저, pk가 나중
        int code = (int) MLDSAStrategyBundle
                .callNativeMLDSAHandle(mldsaType, 0)
                .invokeExact(skC.getMemorySegment(), pkC.getMemorySegment());
        final ProgressResult result = ProgressResult.fromCode(code);
        if (!result.equals(ProgressResult.SUCCESS))
            throw new EntLibNativeError("네이티브 함수 수행 결과가 유효하지 않습니다!");
        return new Pair<>(pkC, skC);
    }
}
