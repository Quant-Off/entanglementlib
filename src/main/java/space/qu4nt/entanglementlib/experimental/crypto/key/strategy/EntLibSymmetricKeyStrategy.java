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

/**
 * 대칭 키 생성 전략을 정의하는 인터페이스입니다.
 * <p>
 * AES, ARIA, ChaCha20 등의 대칭 키 암호화 알고리즘에 사용되는 비밀 키를 생성합니다.
 * 각 알고리즘별 구현체가 이 인터페이스를 구현하여 해당 알고리즘에 적합한 키를 생성합니다.
 *
 * @author Q. T. Felix
 * @see EntLibCryptoKey
 * @see EntLibAsymmetricKeyStrategy
 * @since 1.1.0
 */
public interface EntLibSymmetricKeyStrategy {

    /**
     * 대칭 키를 생성하여 반환하는 메소드입니다.
     * <p>
     * 생성된 키는 {@link EntLibCryptoKey}로 래핑되어 네이티브 메모리에 안전하게 저장됩니다.
     *
     * @return 생성된 대칭 키
     */
    EntLibCryptoKey generateKey();

}
