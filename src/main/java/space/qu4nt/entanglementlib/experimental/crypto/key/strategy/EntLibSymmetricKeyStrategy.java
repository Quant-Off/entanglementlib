/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.key.strategy;

import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;

/**
 * 대칭 키 생성 전략을 정의하는 인터페이스입니다.
 * <p>
 * AES, ARIA, ChaCha20 등의 대칭 키 암호화 알고리즘에 사용되는 비밀 키를 생성합니다.
 * 각 알고리즘별 구현체가 이 인터페이스를 구현하여 해당 알고리즘에 적합한 키를 생성합니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see EntLibCryptoKey
 * @see EntLibAsymmetricKeyStrategy
 */
public interface EntLibSymmetricKeyStrategy {

    /**
     * 대칭 키를 생성하여 반환하는 메소드입니다.
     * <p>
     * 생성된 키는 {@link EntLibCryptoKey}로 래핑되어 네이티브 메모리에 안전하게 저장됩니다.
     * </p>
     *
     * @return 생성된 대칭 키
     */
    EntLibCryptoKey generateKey();

}
