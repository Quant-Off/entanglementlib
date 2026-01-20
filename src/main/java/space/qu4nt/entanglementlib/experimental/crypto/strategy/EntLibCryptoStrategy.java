/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy;

import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;

/**
 * 암호화 스트레티지의 최상위 인터페이스입니다.
 * <p>
 * 모든 암호화 스트레티지(블록 암호, 스트림 암호, AEAD, 서명 등)는 이 인터페이스를 구현합니다.
 * {@link space.qu4nt.entanglementlib.experimental.crypto.EntLibCryptoRegistry}에 등록되어 관리됩니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see CipherStrategy
 * @see SignatureStrategy
 */
public interface EntLibCryptoStrategy {

    /**
     * 이 스트레티지의 알고리즘 이름을 반환하는 메소드입니다.
     *
     * @return 알고리즘 이름
     */
    String getAlgorithmName();

    /**
     * 이 스트레티지의 알고리즘 타입을 반환하는 메소드입니다.
     *
     * @return 알고리즘 타입
     */
    EntLibAlgorithmType getAlgorithmType();

}
