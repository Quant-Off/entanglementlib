/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.bundle;

import space.qu4nt.entanglementlib.security.crypto.AbstractStrategyBundle;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.AESSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.detail.X25519MLKEM768KeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.AESStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.detail.hybrid.X25519MLKEM768Strategy;

/// @author Q. T. Felix
/// @since 1.1.0
final class X25519MLKEM768StrategyBundle extends AbstractStrategyBundle {

    /**
     * 외부 인스턴스화를 방지하기 위한 private 생성자입니다.
     */
    X25519MLKEM768StrategyBundle() {
    }

    /**
     * X25519MLKEM768 암호화 스트레티지들을 레지스트리에 등록하는 메소드입니다.
     */
    @Override
    protected void registerStrategies() {
        register(KEMType.X25519MLKEM768,
                X25519MLKEM768Strategy.create(null, null),
                X25519MLKEM768KeyStrategy.create(null, null));
    }
}
