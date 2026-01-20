/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail.ARIASymmetricKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.EntLibCryptoStrategy;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/// ARIA 블록 암호 알고리즘 전략 클래스입니다.
///
/// ARIA는 대한민국 국가 표준 암호 알고리즘으로, 128비트 블록 크기를 사용합니다.
/// BouncyCastle의 [ARIAEngine]을 사용하여 암호화/복호화를 수행합니다.
/// ARIA-128, ARIA-192, ARIA-256 키 길이를 지원하며, 다양한 운영 모드와
/// 패딩 방식을 설정할 수 있습니다.
///
/// 키는 네이티브 메모리에서 관리되며, 사용 후 즉시 소거됩니다.
///
/// @author Q. T. Felix
/// @see AbstractBlockCipher
/// @see CipherType#ARIA_128
/// @see CipherType#ARIA_192
/// @see CipherType#ARIA_256
/// @since 1.1.0
@Slf4j
public final class ARIAStrategy extends AbstractBlockCipher {

    /**
     * ARIAStrategy 생성자입니다.
     *
     * @param base ARIA 암호화 타입 ({@link CipherType#ARIA_128}, {@link CipherType#ARIA_192}, {@link CipherType#ARIA_256})
     */
    ARIAStrategy(@NotNull CipherType base) {
        super(base, new ARIAEngine());
    }

    /**
     * ARIAStrategy 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param base ARIA 암호화 타입 ({@link CipherType#ARIA_128}, {@link CipherType#ARIA_192}, {@link CipherType#ARIA_256})
     * @return 새 {@link ARIAStrategy} 인스턴스
     */
    public static ARIAStrategy create(@NotNull CipherType base) {
        return new ARIAStrategy(base);
    }

    /**
     * 평문을 ARIA 알고리즘으로 암호화하는 메소드입니다.
     * <p>
     * ECB 모드를 제외한 모든 모드에서 IV(초기화 벡터)가 자동으로 생성되며,
     * 결과는 {@code IV + CipherText} 형식으로 반환됩니다.
     * AEAD 모드(GCM, CCM)에서는 12바이트 IV를, 그 외 모드에서는 16바이트 IV를 사용합니다.
     *
     * @param key        암호화에 사용할 키
     * @param plainBytes 암호화할 평문 바이트 배열
     * @return 암호화된 바이트 배열 (IV + CipherText)
     * @throws IllegalStateException 암호화 실패 시
     */
    @Override
    public byte @NotNull [] encrypt(@NotNull EntLibCryptoKey key, final byte[] plainBytes) {
        try {
            boolean isAead = mode.isAead();
            byte[] iv;
            CipherParameters params;

            // 네이티브 메모리에서 키 바이트 배열 추출
            byte[] keyBytes = key.toByteArray();
            if (keyBytes == null)
                throw new RuntimeException("key null");
            KeyParameter keyParam = new KeyParameter(keyBytes);

            // 사용 후 힙에 복사된 키 바이트 즉시 소거
            KeyDestroyHelper.zeroing(keyBytes);

            // IV 생성 (ECB 제외)
            if (mode != Mode.ECB) {
                int ivLength = isAead ? 12 : 16; // GCM/CCM: 12 bytes, Others: 16 bytes (ARIA block size)
                iv = new byte[ivLength];
                InternalFactory.getSafeRandom().nextBytes(iv);

                if (isAead) {
                    // AEAD 모드는 AEADParameters 사용 (macSize = 128 bits)
                    params = new AEADParameters(keyParam, 128, iv);
                } else {
                    params = new ParametersWithIV(keyParam, iv);
                }
            } else {
                iv = new byte[0];
                params = keyParam;
            }

            byte[] output = processCipher(true, params, plainBytes);

            // 결과 반환: IV + CipherText (ECB 제외)
            if (mode != Mode.ECB) {
                byte[] result = new byte[iv.length + output.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(output, 0, result, iv.length, output.length);
                return result;
            } else {
                return output;
            }

        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 암호문을 ARIA 알고리즘으로 복호화하는 메소드입니다.
     * <p>
     * 입력된 암호문에서 IV를 추출하여 복호화를 수행합니다.
     * AEAD 모드에서는 12바이트, 그 외 모드에서는 16바이트의 IV를 추출합니다.
     *
     * @param key        복호화에 사용할 키
     * @param ciphertext 복호화할 암호문 바이트 배열 (IV + CipherText)
     * @return 복호화된 평문 바이트 배열
     * @throws IllegalStateException    복호화 실패 시
     * @throws IllegalArgumentException 암호문이 IV보다 짧은 경우
     */
    @Override
    public byte @NotNull [] decrypt(@NotNull EntLibCryptoKey key, final byte[] ciphertext) {
        try {
            boolean isAead = mode.isAead();
            byte[] actualCiphertext;
            CipherParameters params;

            // 네이티브 메모리에서 키 바이트 배열 추출
            byte[] keyBytes = key.toByteArray();
            if (keyBytes == null)
                throw new RuntimeException("key null");
            KeyParameter keyParam = new KeyParameter(keyBytes);

            // 사용 후 힙에 복사된 키 바이트 즉시 소거
            KeyDestroyHelper.zeroing(keyBytes);

            if (mode != Mode.ECB) {
                int ivLength = isAead ? 12 : 16;
                if (ciphertext.length < ivLength) {
                    throw new IllegalArgumentException("Ciphertext too short to contain IV");
                }

                byte[] iv = Arrays.copyOfRange(ciphertext, 0, ivLength);
                actualCiphertext = Arrays.copyOfRange(ciphertext, ivLength, ciphertext.length);

                if (isAead) {
                    params = new AEADParameters(keyParam, 128, iv);
                } else {
                    params = new ParametersWithIV(keyParam, iv);
                }
            } else {
                actualCiphertext = ciphertext;
                params = keyParam;
            }

            return processCipher(false, params, actualCiphertext);

        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * 알고리즘 이름을 반환하는 메소드입니다.
     *
     * @return 알고리즘 이름 "ARIA"
     */
    @Override
    public String getAlgorithmName() {
        return "ARIA";
    }

    /**
     * ARIA 전략들을 레지스트리에 등록하는 메소드입니다.
     *
     * @return ARIA 전략 맵
     * @deprecated {@link space.qu4nt.entanglementlib.experimental.crypto.bundle.ARIAStrategyBundle} 사용을 권장합니다.
     */
    @Deprecated(since = "1.1.0", forRemoval = true)
    public static Map<EntLibAlgorithmType, EntLibCryptoStrategy> registry() {
        return new ConcurrentHashMap<>(Map.of(
                CipherType.ARIA_128, new ARIAStrategy(CipherType.ARIA_128),
                CipherType.ARIA_192, new ARIAStrategy(CipherType.ARIA_192),
                CipherType.ARIA_256, new ARIAStrategy(CipherType.ARIA_256)
        ));
    }

    // 테스트용 psvm
    public static void main(String[] args) {
        byte[] plain = "Hello, ARIA Secure World!".getBytes(StandardCharsets.UTF_8);

        // 전략 패턴을 사용한 키 생성
        ARIAStrategy ariaStrategy = new ARIAStrategy(CipherType.ARIA_256);

        // ARIAKeyStrategy를 통해 키 생성
        ARIASymmetricKeyStrategy keyStrategy = ARIASymmetricKeyStrategy.create(ariaStrategy);

        // try-with-resources로 키 자동 소거 보장
        try (EntLibCryptoKey key = keyStrategy.generateKey()) {
            // 키 확인 (테스트용 - 실제 운영 환경에서는 키를 로그에 찍으면 안 됨)
            MemorySegment keySegment = key.getKeySegment();
            byte[] keyBytes = keySegment.toArray(ValueLayout.JAVA_BYTE);
            log.info("Key (Hex): {}", Hex.toHexString(keyBytes));
            KeyDestroyHelper.zeroing(keyBytes); // 확인 후 즉시 소거

            // 암호화
            byte[] encrypted = ariaStrategy.encrypt(key, plain);
            log.info("Encrypted: {}", Hex.toHexString(encrypted));

            // 복호화
            byte[] decrypted = ariaStrategy.decrypt(key, encrypted);
            log.info("Decrypted: {}", Hex.toHexString(decrypted));
            log.info("Decrypted Plain: {}", new String(decrypted, StandardCharsets.UTF_8));
        } // 여기서 key.close()가 호출되어 네이티브 메모리 소거 및 해제됨
    }
}
