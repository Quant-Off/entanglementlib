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
import space.qu4nt.entanglementlib.security.crypto.Mode;
import space.qu4nt.entanglementlib.security.crypto.Padding;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.EntLibSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.BlockCipherStrategy;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
class AESStrategyTest {

    @Test
    @DisplayName("AES Test")
    void test() throws EntLibSecureIllegalArgumentException, EntLibSecureIllegalStateException, EntLibCryptoCipherProcessException {
        final SensitiveDataContainer key = EntLibCryptoRegistry.getKeyStrategy(CipherType.AES_256, EntLibSymmetricKeyStrategy.class).generateKey();

        final SensitiveDataContainer iv = new SensitiveDataContainer(16);
        BlockCipherStrategy aes = EntLibCryptoRegistry.getAlgStrategy(CipherType.AES_256, BlockCipherStrategy.class)
                .setMode(Mode.CBC)
                .setPadding(Padding.PKCS7);
        //
        aes.iv(iv); // 외부에서 IV 할당
        //

        SensitiveDataContainer enc = aes.encrypt(key, "This is Plain!".getBytes(StandardCharsets.UTF_8), false);
        enc.exportData();
        log.info("ENC: {}", enc.getSegmentDataBase64());

        SensitiveDataContainer dec = aes.decrypt(key, enc, false);
        dec.exportData();
        log.info("DEC: {}", new String(Objects.requireNonNull(dec.getSegmentData())));
    }
}