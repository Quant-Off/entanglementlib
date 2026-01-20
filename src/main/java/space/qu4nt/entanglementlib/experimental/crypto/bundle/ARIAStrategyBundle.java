/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.bundle;

import space.qu4nt.entanglementlib.experimental.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.ARIAStrategy;

/**
 * ARIA 알고리즘 스트레티지 번들 클래스입니다.
 * <p>
 * ARIA-128, ARIA-192, ARIA-256 스트레티지를 {@link space.qu4nt.entanglementlib.experimental.crypto.EntLibCryptoRegistry}에 등록합니다.
 * ARIA는 대한민국 국가 표준 블록 암호 알고리즘입니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see AbstractStrategyBundle
 * @see ARIAStrategy
 */
public final class ARIAStrategyBundle extends AbstractStrategyBundle {

    /**
     * 싱글톤 인스턴스입니다.
     */
    private static final ARIAStrategyBundle INSTANCE = new ARIAStrategyBundle();

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    private ARIAStrategyBundle() {}

    /**
     * ARIA 암호화 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link CipherType#ARIA_128}, {@link CipherType#ARIA_192}, {@link CipherType#ARIA_256}
     * 타입에 해당하는 스트레티지를 등록합니다.
     * </p>
     */
    @Override
    protected void registerStrategies() {
        register(CipherType.ARIA_128, ARIAStrategy.create(CipherType.ARIA_128));
        register(CipherType.ARIA_192, ARIAStrategy.create(CipherType.ARIA_192));
        register(CipherType.ARIA_256, ARIAStrategy.create(CipherType.ARIA_256));
    }

    /**
     * 싱글톤 인스턴스를 반환하는 메소드입니다.
     *
     * @return {@link ARIAStrategyBundle} 싱글톤 인스턴스
     */
    public static ARIAStrategyBundle getInstance() {
        return INSTANCE;
    }

}
