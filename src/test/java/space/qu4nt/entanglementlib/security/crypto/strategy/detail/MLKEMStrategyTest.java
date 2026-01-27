/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeKEMStrategy;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

/// 무지성테스트
@Slf4j
class MLKEMStrategyTest {

    @Test
    @DisplayName("ML-KEM Test")
    void test() throws Throwable {
        // given
        EntLibAsymmetricKeyStrategy key = EntLibCryptoRegistry.getKeyStrategy(KEMType.ML_KEM_768, EntLibAsymmetricKeyStrategy.class);
        NativeKEMStrategy mlkem = EntLibCryptoRegistry.getAlgStrategy(KEMType.ML_KEM_768, NativeKEMStrategy.class);
        var pair = key.generateKeyPair();

        // when then
        pair.getFirst().exportData();
        log.info("PK: {}", pair.getFirst().getSegmentData().length);
        SensitiveDataContainer capsule = mlkem.encapsulate(pair.getFirst());
        capsule.exportData();
        log.info("CAPSULE: {}", Hex.toHexString(capsule.getSegmentData()));

        SensitiveDataContainer sharedSecret = mlkem.decapsulate(pair.getSecond(), capsule.get(0).get());
        sharedSecret.exportData();
        log.info("SS: {}", Hex.toHexString(sharedSecret.getSegmentData()));
    }
}