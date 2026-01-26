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
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.X25519KeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.X25519Strategy;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.Locale;

/// X25519 Diffie-Hellman 키 교환 스트레티지 번들 클래스입니다.
///
/// X25519 스트레티지를 [EntLibCryptoRegistry]에 등록합니다.
/// X25519는 Curve25519 타원 곡선을 사용한 고보안 ECDH 키 교환 알고리즘입니다.
///
/// 이 암호화 연산은 `entlib-native`에서 수행됩니다. 정적 블럭에 네이티브 호출을 위한
/// 레이아웃을 정의하고 사용 함수를 정의해야 합니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see X25519Strategy
/// @since 1.1.0
@Slf4j
public final class X25519StrategyBundle extends AbstractStrategyBundle {

    //
    // EntLib-Native - start
    //

    static {
        NativeLinkerManager entLibNative = InternalFactory.callNativeLib();
        MemoryLayout[] keyGenLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.ADDRESS};
        MemoryLayout[] secretToPublicLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.ADDRESS};
        MemoryLayout[] dhLayouts = new MemoryLayout[]{ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS};

        log.debug("> X25519 네이티브 함수 로드 중...");
        entLibNative
                .addReturnableMethodHandle("x25519_keygen", ValueLayout.JAVA_INT, keyGenLayouts)
                .addReturnableMethodHandle("x25519_sk_to_pk", ValueLayout.JAVA_INT, secretToPublicLayouts)
                .addReturnableMethodHandle("x25519_dh", ValueLayout.JAVA_INT, dhLayouts);
        log.debug("> X25519 알고리즘에 대한 모든 네이티브 함수 등록 완료");
    }

    @NotNull
    @ApiStatus.Internal
    @CallerResponsibility
    public static MethodHandle callNativeX25519Handle(final int typeId) {
        return InternalFactory.callNativeLib().getHandle(KEMType.X25519
                .getName().toLowerCase(Locale.ROOT) + "_" +
                        (typeId == 0 ? "keygen" : typeId == 1 ? "sk_to_pk" : "dh"));
    }

    //
    // EntLib-Native - end
    //

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    X25519StrategyBundle() {
    }

    /**
     * X25519 스트레티지를 레지스트리에 등록하는 메소드입니다.
     */
    @Override
    protected void registerStrategies() {
        register(KEMType.X25519, X25519Strategy.create(), X25519KeyStrategy.create());
    }
}
