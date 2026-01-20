/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.EntLibSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.ChaCha20Poly1305Strategy;

/**
 * ChaCha20-Poly1305 AEAD 암호 알고리즘을 위한 대칭 키 생성 전략 클래스입니다.
 * <p>
 * ChaCha20-Poly1305는 ChaCha20 스트림 암호와 Poly1305 MAC을 결합한 AEAD(Authenticated Encryption with Associated Data)
 * 알고리즘으로, 256비트 키를 사용합니다. {@link ChaCha20Poly1305Strategy}와 함께 사용됩니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see EntLibSymmetricKeyStrategy
 * @see ChaCha20Poly1305Strategy
 */
public final class ChaCha20Poly1305SymmetricKeyStrategy implements EntLibSymmetricKeyStrategy {

    /**
     * 생성할 키의 비트 크기입니다.
     */
    private final int keySize;

    /**
     * {@link ChaCha20Poly1305Strategy}로부터 키 크기를 추출하여 인스턴스를 생성하는 생성자입니다.
     *
     * @param chaCha20Poly1305Strategy ChaCha20-Poly1305 암호화 전략
     */
    ChaCha20Poly1305SymmetricKeyStrategy(ChaCha20Poly1305Strategy chaCha20Poly1305Strategy) {
        this.keySize = chaCha20Poly1305Strategy.getAlgorithmType().getKeySize();
    }

    /**
     * {@link ChaCha20Poly1305SymmetricKeyStrategy} 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param chaCha20Poly1305Strategy ChaCha20-Poly1305 암호화 전략
     * @return 새 {@link ChaCha20Poly1305SymmetricKeyStrategy} 인스턴스
     */
    public static ChaCha20Poly1305SymmetricKeyStrategy create(final @NotNull ChaCha20Poly1305Strategy chaCha20Poly1305Strategy) {
        return new ChaCha20Poly1305SymmetricKeyStrategy(chaCha20Poly1305Strategy);
    }

    /**
     * ChaCha20-Poly1305 대칭 키를 생성하여 반환하는 메소드입니다.
     *
     * @return 생성된 ChaCha20-Poly1305 키
     */
    @Override
    public EntLibCryptoKey generateKey() {
        return new EntLibCryptoKey(InternalKeyGenerator.initializedCipherKeyGenerator(keySize).generateKey());
    }
}
