/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.entlibnative;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
class SDCSemiPerformanceTest {

    @Test
    @DisplayName("랜덤 바이트 생성 퍼포먼스(32)")
    void randomBytesTest() throws InterruptedException {
        log.info("안정화 로드: 5초 대기");
        Thread.sleep(5000);
        final int loop = 10_000_000;
        final int gen = 32;

        long start = System.nanoTime();
        log.info("bytes(to hex): {}", loop);
        for (int i = 0; i < loop; i++) {
            SensitiveDataContainer.generateSafeRandomBytes(gen);
//            if ((i & 1) == 0)
//                log.info("{}: {}", i, Hex.toHexString(SensitiveDataContainer.generateSafeRandomBytes(gen)));
        }
        log.info("total: {}s", (System.nanoTime() - start) / 1_000_000_000.0);

        start = System.nanoTime();
        log.info("");
        log.info("bytes(to base64): {}", loop);
        for (int i = 0; i < loop; i++) {
            SensitiveDataContainer.generateBase64String(gen);
//            if ((i & 1) == 0)
//                log.info("{}: {}", i, SensitiveDataContainer.generateBase64String(gen));
        }
        log.info("total: {}s", (System.nanoTime() - start) / 1_000_000_000.0);
    }
}