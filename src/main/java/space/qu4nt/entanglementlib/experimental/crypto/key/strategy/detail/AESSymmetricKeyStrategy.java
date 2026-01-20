/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.EntLibSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.AESStrategy;

import java.util.stream.IntStream;

/**
 * AES 알고리즘을 위한 대칭 키 생성 전략 클래스입니다.
 * <p>
 * 128, 192, 256비트 키 크기를 지원하며, {@link AESStrategy}와 함께 사용됩니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see EntLibSymmetricKeyStrategy
 * @see AESStrategy
 */
public final class AESSymmetricKeyStrategy implements EntLibSymmetricKeyStrategy {

    /**
     * AES에서 지원하는 키 크기 목록입니다. (128, 192, 256비트)
     */
    final int[] POSSIBLE_KEY_SIZES = new int[]{128, 192, 256};

    /**
     * 생성할 키의 비트 크기입니다.
     */
    private final int keySize;

    /**
     * {@link AESStrategy}로부터 키 크기를 추출하여 인스턴스를 생성하는 생성자입니다.
     *
     * @param aesStrategy AES 암호화 전략
     */
    AESSymmetricKeyStrategy(AESStrategy aesStrategy) {
        this.keySize = IntStream.of(POSSIBLE_KEY_SIZES)
                .filter(p -> p == aesStrategy.getAlgorithmType().getKeySize())
                .findFirst()
                .orElse(256);
    }

    /**
     * {@link AESSymmetricKeyStrategy} 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param aesStrategy AES 암호화 전략
     * @return 새 {@link AESSymmetricKeyStrategy} 인스턴스
     */
    public static AESSymmetricKeyStrategy create(final @NotNull AESStrategy aesStrategy) {
        return new AESSymmetricKeyStrategy(aesStrategy);
    }

    /**
     * AES 대칭 키를 생성하여 반환하는 메소드입니다.
     *
     * @return 생성된 AES 키
     */
    @Override
    public EntLibCryptoKey generateKey() {
        return new EntLibCryptoKey(InternalKeyGenerator.initializedCipherKeyGenerator(keySize).generateKey());
    }
}
