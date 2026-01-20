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

package space.qu4nt.entanglementlib.experimental.crypto.key.strategy;

import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

/**
 * 비대칭 키 쌍 생성 전략을 정의하는 인터페이스입니다.
 * <p>
 * RSA, ML-DSA 등의 비대칭 키 암호화/서명 알고리즘에 사용되는 공개 키와 개인 키 쌍을 생성합니다.
 * 각 알고리즘별 구현체가 이 인터페이스를 구현하여 해당 알고리즘에 적합한 키 쌍을 생성합니다.
 *
 * @author Q. T. Felix
 * @see EntLibCryptoKey
 * @see EntLibSymmetricKeyStrategy
 * @since 1.1.0
 */
public interface EntLibAsymmetricKeyStrategy {

    /**
     * 비대칭 키 쌍(공개 키, 개인 키)을 생성하여 반환하는 메소드입니다.
     * <p>
     * 반환되는 {@link Pair}의 첫 번째 요소는 공개 키, 두 번째 요소는 개인 키입니다.
     * 생성된 키들은 {@link EntLibCryptoKey}로 래핑되어 네이티브 메모리에 안전하게 저장됩니다.
     *
     * @return 공개 키와 개인 키의 쌍
     */
    Pair<EntLibCryptoKey, EntLibCryptoKey> generateKeyPair();

}
