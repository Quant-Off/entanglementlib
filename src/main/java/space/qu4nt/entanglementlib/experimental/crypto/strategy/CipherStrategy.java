/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;

/**
 * 암호화/복호화 연산을 수행하는 전략 인터페이스입니다.
 * <p>
 * 블록 암호({@link BlockCipherStrategy}), 스트림 암호({@link StreamCipherStrategy}),
 * AEAD 암호({@link AEADCipherStrategy}) 등이 이 인터페이스를 확장합니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see BlockCipherStrategy
 * @see StreamCipherStrategy
 * @see AEADCipherStrategy
 */
public interface CipherStrategy extends EntLibCryptoStrategy {

    /**
     * 평문을 암호화하는 메소드입니다.
     *
     * @param key        암호화에 사용할 키
     * @param plainBytes 암호화할 평문 바이트 배열
     * @return 암호화된 암호문 바이트 배열
     */
    byte @NotNull [] encrypt(@NotNull EntLibCryptoKey key, final byte[] plainBytes);

    /**
     * 암호문을 복호화하는 메소드입니다.
     *
     * @param key        복호화에 사용할 키
     * @param ciphertext 복호화할 암호문 바이트 배열
     * @return 복호화된 평문 바이트 배열
     */
    byte @NotNull [] decrypt(@NotNull EntLibCryptoKey key, final byte[] ciphertext);

}
