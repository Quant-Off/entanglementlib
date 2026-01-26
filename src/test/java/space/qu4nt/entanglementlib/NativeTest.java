/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.crypto.EntLibCryptoSignatureProcessingException;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.security.crypto.SignatureType;
import space.qu4nt.entanglementlib.security.crypto.key.strategy.NativeEntLibAsymmetricKeyStrategy;
import space.qu4nt.entanglementlib.security.crypto.strategy.NativeSignatureStrategy;
import space.qu4nt.entanglementlib.util.StringUtil;
import space.qu4nt.entanglementlib.util.wrapper.Hex;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.nio.charset.StandardCharsets;

@Slf4j
class NativeTest {

    @Test
    @DisplayName("Native ML-DSA keygen, sign, verify")
    void mlDsaTest() throws Throwable {
        // settings
        byte[] plains = "Hello, ML-DSA Secure Signature World!".getBytes(StandardCharsets.UTF_8);
        NativeSignatureStrategy mldsaStrategy = EntLibCryptoRegistry.getAlgStrategy(SignatureType.ML_DSA_65, NativeSignatureStrategy.class);

        // keygen
        NativeEntLibAsymmetricKeyStrategy key = EntLibCryptoRegistry.getKeyStrategy(SignatureType.ML_DSA_65, NativeEntLibAsymmetricKeyStrategy.class);
        Pair<SensitiveDataContainer, SensitiveDataContainer> keyPair = key.generateKeyPair();
        keyPair.getFirst().exportData();
        keyPair.getSecond().exportData();
        log.info("PK: {}, SK: {}",
                StringUtil.truncateMiddle(Hex.toHexString(keyPair.getFirst().getSegmentData()), 6, 6),
                StringUtil.truncateMiddle(Hex.toHexString(keyPair.getSecond().getSegmentData()), 6, 6));

        // sign
        SensitiveDataContainer complex = mldsaStrategy.sign(keyPair.getSecond(), plains);
        complex.addContainerData(keyPair.getFirst()); // 공개 키 전달
        if (complex == null)
            throw new RuntimeException("서명 실패");
        complex.exportData();
        log.info("Signature: {}", StringUtil.truncateMiddle(Hex.toHexString(complex.getSegmentData()), 6, 6));

        // ...통신

        // verify
        var t = new Thread(() -> {
            try {
                log.info("Verify: {}", mldsaStrategy.verify(complex));
            } catch (EntLibCryptoSignatureProcessingException e) {
                throw new RuntimeException(e);
            }
        });
        t.start();
        t.join();

        // all wipe
        complex.close();
    }
}
