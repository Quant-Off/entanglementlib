/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.bundle;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.CallerResponsibility;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.entlibnative.NativeLinkerManager;
import space.qu4nt.entanglementlib.security.crypto.*;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.MLDSAKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.MLKEMKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLDSAStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLKEMStrategy;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.Locale;

/// ML-KEM(Module Lattice-based Key Encapsulate Mechanism) 스트레티지 번들 클래스입니다.
///
/// ML-KEM 각 파라미터 세트 스트레티지를 [EntLibCryptoRegistry]에 등록합니다.
/// ML-KEM는 NIST에서 표준화한 PQC(Post-Quantum Cryptography) 전자 서명 알고리즘입니다.
///
/// 이 암호화 연산은 `entlib-native`에서 수행됩니다. 정적 블럭에 네이티브 호출을 위한
/// 레이아웃을 정의하고 사용 함수를 정의해야 합니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see MLKEMStrategy
/// @since 1.1.0
@Slf4j
public final class MLKEMStrategyBundle extends AbstractStrategyBundle {

    //
    // EntLib-Native - start
    //

    static {
        NativeLinkerManager entLibNative = InternalFactory.callNativeLib();
        MemoryLayout[] keyGenLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.ADDRESS};
        MemoryLayout[] encapsulateLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS};
        MemoryLayout[] decapsulateLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS};

        log.debug("> ML-KEM 네이티브 함수 로드 중...");
        entLibNative
                // ML-KEM-512
                .addReturnableMethodHandle("ml_kem_512_keygen", ValueLayout.JAVA_INT, keyGenLayouts)
                .addReturnableMethodHandle("ml_kem_512_encapsulate", ValueLayout.JAVA_INT, encapsulateLayouts)
                .addReturnableMethodHandle("ml_kem_512_decapsulate", ValueLayout.JAVA_INT, decapsulateLayouts)

                // ML-KEM-768
                .addReturnableMethodHandle("ml_kem_768_keygen", ValueLayout.JAVA_INT, keyGenLayouts)
                .addReturnableMethodHandle("ml_kem_768_encapsulate", ValueLayout.JAVA_INT, encapsulateLayouts)
                .addReturnableMethodHandle("ml_kem_768_decapsulate", ValueLayout.JAVA_INT, decapsulateLayouts)

                // ML-KEM-1024
                .addReturnableMethodHandle("ml_kem_1024_keygen", ValueLayout.JAVA_INT, keyGenLayouts)
                .addReturnableMethodHandle("ml_kem_1024_encapsulate", ValueLayout.JAVA_INT, encapsulateLayouts)
                .addReturnableMethodHandle("ml_kem_1024_decapsulate", ValueLayout.JAVA_INT, decapsulateLayouts);
        log.debug("> ML-KEM 알고리즘에 대한 모든 네이티브 함수 등록 완료");
    }

    @NotNull
    @ApiStatus.Internal
    @CallerResponsibility
    public static MethodHandle callNativeMLKEMHandle(final @NotNull EntLibAlgorithmType mlkemType, final int typeId) {
        return InternalFactory.callNativeLib().getHandle(
                mlkemType.getName().toLowerCase(Locale.ROOT) + "_" +
                        (typeId == 0 ? "keygen" : typeId == 1 ? "encapsulate" : "decapsulate"));
    }

    //
    // EntLib-Native - end
    //

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    MLKEMStrategyBundle() {
    }

    /**
     * ML-KEM 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     */
    @Override
    protected void registerStrategies() {
        register(KEMType.ML_KEM_512, MLKEMStrategy.create(KEMType.ML_KEM_512), MLKEMKeyStrategy.create(KEMType.ML_KEM_512));
        register(KEMType.ML_KEM_768, MLKEMStrategy.create(KEMType.ML_KEM_768), MLKEMKeyStrategy.create(KEMType.ML_KEM_768));
        register(KEMType.ML_KEM_1024, MLKEMStrategy.create(KEMType.ML_KEM_1024), MLKEMKeyStrategy.create(KEMType.ML_KEM_1024));
    }
}
