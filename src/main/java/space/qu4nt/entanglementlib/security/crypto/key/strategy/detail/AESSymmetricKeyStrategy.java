/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy.detail;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.AESStrategy;

import java.util.stream.IntStream;

/// AES 알고리즘을 위한 대칭 키 생성 전략 클래스입니다.
///
/// 128, 192, 256비트 키 크기를 지원하며, [AESStrategy]와 함께 사용됩니다.
///
/// @author Q. T. Felix
/// @see EntLibSymmetricKeyStrategy
/// @see AESStrategy
/// @since 1.1.0
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
    AESSymmetricKeyStrategy(int keySize) {
        this.keySize = IntStream.of(POSSIBLE_KEY_SIZES)
                .filter(p -> p == keySize)
                .findFirst()
                .orElse(256);
    }

    /**
     * {@link AESSymmetricKeyStrategy} 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param keySize AES 암호화 키 사이즈
     * @return 새 {@link AESSymmetricKeyStrategy} 인스턴스
     */
    public static AESSymmetricKeyStrategy create(final int keySize) {
        return new AESSymmetricKeyStrategy(keySize);
    }

    /**
     * AES 대칭 키를 생성하여 반환하는 메소드입니다.
     *
     * @return 생성된 AES 키
     */
    @Override
    public SensitiveDataContainer generateKey() {
        return new SensitiveDataContainer(InternalKeyGenerator.initializedCipherKeyGenerator(keySize).generateKey(), true);
    }
}
