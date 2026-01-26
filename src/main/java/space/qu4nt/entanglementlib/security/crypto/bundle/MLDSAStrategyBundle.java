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
import space.qu4nt.entanglementlib.security.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.SignatureType;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.MLDSAKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.MLDSAStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/// ML-DSA(Module Lattice-based Digital Signature Algorithm) 스트레티지 번들 클래스입니다.
///
/// ML-DSA 각 파라미터 세트 스트레티지를 [EntLibCryptoRegistry]에 등록합니다.
/// ML-DSA는 NIST에서 표준화한 PQC(Post-Quantum Cryptography) 전자 서명 알고리즘입니다.
///
/// 이 암호화 연산은 `entlib-native`에서 수행됩니다. 정적 블럭에 네이티브 호출을 위한
/// 레이아웃을 정의하고 사용 함수를 정의해야 합니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see MLDSAStrategy
/// @since 1.1.0
@Slf4j
public final class MLDSAStrategyBundle extends AbstractStrategyBundle {

    //
    // EntLib-Native - start
    //

    static {
        NativeLinkerManager entLibNative = InternalFactory.callNativeLib();
        MemoryLayout[] keyGenLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.ADDRESS};
        MemoryLayout[] signLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS};
        MemoryLayout[] verifyLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS};

        log.debug("> ML-DSA 네이티브 함수 로드 중...");
        entLibNative
                // ML-DSA-44
                .addReturnableMethodHandle("ml_dsa_44_keygen", ValueLayout.JAVA_INT, keyGenLayouts)
                .addReturnableMethodHandle("ml_dsa_44_sign", ValueLayout.JAVA_INT, signLayouts)
                .addReturnableMethodHandle("ml_dsa_44_verify", ValueLayout.JAVA_INT, verifyLayouts)

                // ML-DSA-65
                .addReturnableMethodHandle("ml_dsa_65_keygen", ValueLayout.JAVA_INT, keyGenLayouts)
                .addReturnableMethodHandle("ml_dsa_65_sign", ValueLayout.JAVA_INT, signLayouts)
                .addReturnableMethodHandle("ml_dsa_65_verify", ValueLayout.JAVA_INT, verifyLayouts)

                // ML-DSA-87
                .addReturnableMethodHandle("ml_dsa_87_keygen", ValueLayout.JAVA_INT, keyGenLayouts)
                .addReturnableMethodHandle("ml_dsa_87_sign", ValueLayout.JAVA_INT, signLayouts)
                .addReturnableMethodHandle("ml_dsa_87_verify", ValueLayout.JAVA_INT, verifyLayouts);
        log.debug("> ML-DSA 알고리즘에 대한 모든 네이티브 함수 등록 완료");
    }

    @NotNull
    @ApiStatus.Internal
    @CallerResponsibility
    public static MethodHandle callNativeMLDSAHandle(final @NotNull EntLibAlgorithmType mldsaType, final int typeId) {
        return InternalFactory.callNativeLib().getHandle(
                mldsaType.getName().toLowerCase(Locale.ROOT) + "_" +
                        (typeId == 0 ? "keygen" : typeId == 1 ? "sign" : "verify"));
    }

    //
    // EntLib-Native - end
    //

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    MLDSAStrategyBundle() {
    }

    /**
     * ML-DSA 서명 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link SignatureType#ML_DSA_44}, {@link SignatureType#ML_DSA_65}, {@link SignatureType#ML_DSA_87}
     * 타입에 해당하는 스트레티지를 등록합니다.
     */
    @Override
    protected void registerStrategies() {
        register(SignatureType.ML_DSA_44, MLDSAStrategy.create(SignatureType.ML_DSA_44), MLDSAKeyStrategy.create(SignatureType.ML_DSA_44));
        register(SignatureType.ML_DSA_65, MLDSAStrategy.create(SignatureType.ML_DSA_65), MLDSAKeyStrategy.create(SignatureType.ML_DSA_65));
        register(SignatureType.ML_DSA_87, MLDSAStrategy.create(SignatureType.ML_DSA_87), MLDSAKeyStrategy.create(SignatureType.ML_DSA_87));
    }
}
