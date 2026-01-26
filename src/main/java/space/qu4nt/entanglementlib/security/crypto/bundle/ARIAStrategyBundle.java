/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.bundle;

import space.qu4nt.entanglementlib.security.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.ARIASymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.ARIAStrategy;

/// ARIA 알고리즘 스트레티지 번들 클래스입니다.
///
/// ARIA-128, ARIA-192, ARIA-256 스트레티지를 [EntLibCryptoRegistry]에 등록합니다.
/// ARIA는 대한민국 국가 표준 블록 암호 알고리즘입니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see ARIAStrategy
/// @since 1.1.0
public final class ARIAStrategyBundle extends AbstractStrategyBundle {

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    ARIAStrategyBundle() {
    }

    /**
     * ARIA 암호화 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link CipherType#ARIA_128}, {@link CipherType#ARIA_192}, {@link CipherType#ARIA_256}
     * 타입에 해당하는 스트레티지를 등록합니다.
     */
    @Override
    protected void registerStrategies() {
        register(CipherType.ARIA_128, ARIAStrategy.create(CipherType.ARIA_128), ARIASymmetricKeyStrategy.create(128));
        register(CipherType.ARIA_192, ARIAStrategy.create(CipherType.ARIA_192), ARIASymmetricKeyStrategy.create(192));
        register(CipherType.ARIA_256, ARIAStrategy.create(CipherType.ARIA_256), ARIASymmetricKeyStrategy.create(256));
    }
}
