/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key.strategy.detail;

import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.ChaCha20Strategy;

/// ChaCha20 스트림 암호 알고리즘을 위한 대칭 키 생성 전략 클래스입니다.
///
/// ChaCha20은 256비트 키를 사용하는 고성능 스트림 암호입니다.
/// [ChaCha20Strategy]와 함께 사용됩니다.
///
/// @author Q. T. Felix
/// @see EntLibSymmetricKeyStrategy
/// @see ChaCha20Strategy
/// @since 1.1.0
public final class ChaCha20SymmetricKeyStrategy implements EntLibSymmetricKeyStrategy {

    /**
     * 생성할 키의 비트 크기입니다.
     */
    private final int keySize;

    /**
     * {@link ChaCha20Strategy}로부터 키 크기를 추출하여 인스턴스를 생성하는 생성자입니다.
     */
    ChaCha20SymmetricKeyStrategy() {
        this.keySize = 256;
    }

    /**
     * {@link ChaCha20SymmetricKeyStrategy} 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @return 새 {@link ChaCha20SymmetricKeyStrategy} 인스턴스
     */
    public static ChaCha20SymmetricKeyStrategy create() {
        return new ChaCha20SymmetricKeyStrategy();
    }

    /**
     * ChaCha20 대칭 키를 생성하여 반환하는 메소드입니다.
     *
     * @return 생성된 ChaCha20 키
     */
    @Override
    public SensitiveDataContainer generateKey() {
        return new SensitiveDataContainer(InternalKeyGenerator.initializedCipherKeyGenerator(keySize).generateKey(), true);
    }
}
