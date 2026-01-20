/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.bundle;

import space.qu4nt.entanglementlib.experimental.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.AESStrategy;

/**
 * AES 알고리즘 스트레티지 번들 클래스입니다.
 * <p>
 * AES-128, AES-192, AES-256 스트레티지를 {@link space.qu4nt.entanglementlib.experimental.crypto.EntLibCryptoRegistry}에 등록합니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see AbstractStrategyBundle
 * @see AESStrategy
 */
public final class AESStrategyBundle extends AbstractStrategyBundle {

    /**
     * 싱글톤 인스턴스입니다.
     */
    private static final AESStrategyBundle INSTANCE = new AESStrategyBundle();

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    private AESStrategyBundle() {}

    /**
     * AES 암호화 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link CipherType#AES_128}, {@link CipherType#AES_192}, {@link CipherType#AES_256}
     * 타입에 해당하는 스트레티지를 등록합니다.
     * </p>
     */
    @Override
    protected void registerStrategies() {
        register(CipherType.AES_128, AESStrategy.create(CipherType.AES_128));
        register(CipherType.AES_192, AESStrategy.create(CipherType.AES_192));
        register(CipherType.AES_256, AESStrategy.create(CipherType.AES_256));
    }

    /**
     * 싱글톤 인스턴스를 반환하는 메소드입니다.
     *
     * @return {@link AESStrategyBundle} 싱글톤 인스턴스
     */
    public static AESStrategyBundle getInstance() {
        return INSTANCE;
    }

}
