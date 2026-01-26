/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.bundle;

import space.qu4nt.entanglementlib.security.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.ChaCha20Poly1305SymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.ChaCha20SymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.AESStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.ChaCha20Poly1305Strategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.ChaCha20Strategy;

/// ChaCha20, ChaCha20-Poly1305 알고리즘 스트레티지 번들 클래스입니다.
///
/// 각 암호화 알고리즘을 [EntLibCryptoRegistry]에 등록합니다.
///
/// 헷갈리지 마세요! 이 번들 클래스는 `RFC 8439`표준에 따른 알고리즘을
/// 포함합니다.
///
/// @author Q. T. Felix
/// @see AbstractStrategyBundle
/// @see ChaCha20Strategy
/// @see ChaCha20Poly1305Strategy
/// @since 1.1.0
public final class ChaCha20StrategyBundle extends AbstractStrategyBundle {

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    ChaCha20StrategyBundle() {
    }

    /**
     * AES 암호화 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     * <p>
     * {@link CipherType#AES_128}, {@link CipherType#AES_192}, {@link CipherType#AES_256}
     * 타입에 해당하는 스트레티지를 등록합니다.
     */
    @Override
    protected void registerStrategies() {
        register(CipherType.CHACHA20, ChaCha20Strategy.create(), ChaCha20SymmetricKeyStrategy.create());
        register(CipherType.CHACHA20_POLY1305, ChaCha20Poly1305Strategy.create(), ChaCha20Poly1305SymmetricKeyStrategy.create());
    }
}
