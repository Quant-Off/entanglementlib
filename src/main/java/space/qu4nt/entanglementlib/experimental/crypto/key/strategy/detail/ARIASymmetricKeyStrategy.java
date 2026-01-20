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

package space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.EntLibSymmetricKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.detail.ARIAStrategy;

import java.util.stream.IntStream;

/// ARIA 알고리즘을 위한 대칭 키 생성 전략 클래스입니다.
///
/// 128, 192, 256비트 키 크기를 지원하며, [ARIAStrategy]와 함께 사용됩니다.
/// ARIA는 대한민국 국가 표준 블록 암호 알고리즘입니다.
///
/// @author Q. T. Felix
/// @see EntLibSymmetricKeyStrategy
/// @see ARIAStrategy
/// @since 1.1.0
public final class ARIASymmetricKeyStrategy implements EntLibSymmetricKeyStrategy {

    /**
     * ARIA에서 지원하는 키 크기 목록입니다. (128, 192, 256비트)
     */
    final int[] POSSIBLE_KEY_SIZES = new int[]{128, 192, 256};

    /**
     * 생성할 키의 비트 크기입니다.
     */
    private final int keySize;

    /**
     * {@link ARIAStrategy}로부터 키 크기를 추출하여 인스턴스를 생성하는 생성자입니다.
     *
     * @param ariaStrategy ARIA 암호화 전략
     */
    ARIASymmetricKeyStrategy(ARIAStrategy ariaStrategy) {
        this.keySize = IntStream.of(POSSIBLE_KEY_SIZES)
                .filter(p -> p == ariaStrategy.getAlgorithmType().getKeySize())
                .findFirst()
                .orElse(256);
    }

    /**
     * {@link ARIASymmetricKeyStrategy} 인스턴스를 생성하는 팩토리 메소드입니다.
     *
     * @param ariaStrategy ARIA 암호화 전략
     * @return 새 {@link ARIASymmetricKeyStrategy} 인스턴스
     */
    public static ARIASymmetricKeyStrategy create(final @NotNull ARIAStrategy ariaStrategy) {
        return new ARIASymmetricKeyStrategy(ariaStrategy);
    }

    /**
     * ARIA 대칭 키를 생성하여 반환하는 메소드입니다.
     *
     * @return 생성된 ARIA 키
     */
    @Override
    public EntLibCryptoKey generateKey() {
        return new EntLibCryptoKey(InternalKeyGenerator.initializedCipherKeyGenerator(keySize).generateKey());
    }
}
