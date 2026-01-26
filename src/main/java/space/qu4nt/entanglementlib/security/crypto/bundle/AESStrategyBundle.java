/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.bundle;

import space.qu4nt.entanglementlib.security.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.AESSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.AESStrategy;

/// AES 알고리즘 스트레티지 번들 클래스입니다.
///
/// AES-128, AES-192, AES-256 스트레티지를 [EntLibCryptoRegistry]에 등록합니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see AESStrategy
/// @since 1.1.0
final class AESStrategyBundle extends AbstractStrategyBundle {

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    AESStrategyBundle() {
    }

    /**
     * AES 암호화 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link CipherType#AES_128}, {@link CipherType#AES_192}, {@link CipherType#AES_256}
     * 타입에 해당하는 스트레티지를 등록합니다.
     */
    @Override
    protected void registerStrategies() {
        register(CipherType.AES_128, AESStrategy.create(CipherType.AES_128), AESSymmetricKeyStrategy.create(128));
        register(CipherType.AES_192, AESStrategy.create(CipherType.AES_192), AESSymmetricKeyStrategy.create(192));
        register(CipherType.AES_256, AESStrategy.create(CipherType.AES_256), AESSymmetricKeyStrategy.create(256));
    }
}
