/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoCipherProcessException;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.StreamCipherStrategy;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
class ChaCha20StrategyTest {

    @Test
    @DisplayName("ChaCha20 Test")
    void test() throws EntLibSecureIllegalArgumentException, EntLibSecureIllegalStateException, EntLibCryptoCipherProcessException {
        final SensitiveDataContainer key = EntLibCryptoRegistry.getKeyStrategy(CipherType.CHACHA20, EntLibSymmetricKeyStrategy.class).generateKey();

        final SensitiveDataContainer iv = new SensitiveDataContainer(8);
        StreamCipherStrategy chacha20 = EntLibCryptoRegistry.getAlgStrategy(CipherType.CHACHA20, StreamCipherStrategy.class);
        //
        chacha20.iv(iv); // 외부에서 IV 할당
        //

        SensitiveDataContainer enc = chacha20.encrypt(key, "This is Plain!".getBytes(StandardCharsets.UTF_8), false);
        enc.exportData();
        log.info("ENC: {}", enc.getSegmentDataBase64());

        SensitiveDataContainer dec = chacha20.decrypt(key, enc, false);
        dec.exportData();
        log.info("DEC: {}", new String(Objects.requireNonNull(dec.getSegmentData())));
    }
}