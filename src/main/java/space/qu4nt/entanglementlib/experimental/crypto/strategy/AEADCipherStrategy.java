/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy;

/**
 * AEAD(Authenticated Encryption with Associated Data)를 지원하는 암호화 전략 인터페이스입니다.
 * <p>
 * GCM, CCM 등의 AEAD 모드에서 AAD(Additional Authenticated Data)를 설정할 수 있는 기능을 제공합니다.
 * ChaCha20-Poly1305와 같은 AEAD 알고리즘도 이 인터페이스를 구현합니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see CipherStrategy
 */
public interface AEADCipherStrategy extends CipherStrategy {

    /**
     * AAD(Additional Authenticated Data)를 설정하는 메소드입니다.
     * <p>
     * AAD는 암호화되지 않지만 무결성이 보장됩니다.
     * 암호화/복호화 수행 전에 호출되어야 합니다.
     * </p>
     *
     * @param aad 추가 인증 데이터
     * @return 메소드 체이닝을 위한 {@code this}
     */
    AEADCipherStrategy updateAAD(byte[] aad);

}
