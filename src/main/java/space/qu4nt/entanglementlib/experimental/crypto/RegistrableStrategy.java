/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto;

import space.qu4nt.entanglementlib.experimental.crypto.strategy.EntLibCryptoStrategy;

import java.util.Map;

/**
 * 레지스트리에 등록 가능한 스트레티지를 위한 인터페이스입니다.
 * <p>
 * 암호화 스트레티지 또는 키 스트레티지 구현체가 이 인터페이스를 구현하면
 * {@link EntLibCryptoRegistry}에 자동으로 등록됩니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see AbstractStrategyBundle
 * @see EntLibCryptoRegistry
 */
public interface RegistrableStrategy {

    /**
     * 이 스트레티지 제공자가 등록할 스트레티지들을 반환하는 메소드입니다.
     *
     * @return 알고리즘 타입과 스트레티지의 매핑
     */
    Map<EntLibAlgorithmType, ? extends EntLibCryptoStrategy> getStrategies();

}
