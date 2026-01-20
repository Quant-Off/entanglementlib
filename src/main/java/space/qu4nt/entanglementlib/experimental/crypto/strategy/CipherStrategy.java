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

package space.qu4nt.entanglementlib.experimental.crypto.strategy;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;

/// 암호화/복호화 연산을 수행하는 전략 인터페이스입니다.
///
/// 블록 암호([BlockCipherStrategy]), 스트림 암호([StreamCipherStrategy]),
/// AEAD 암호([AEADCipherStrategy]) 등이 이 인터페이스를 확장합니다.
///
/// @author Q. T. Felix
/// @see BlockCipherStrategy
/// @see StreamCipherStrategy
/// @see AEADCipherStrategy
/// @since 1.1.0
public interface CipherStrategy extends EntLibCryptoStrategy {

    /**
     * 평문을 암호화하는 메소드입니다.
     *
     * @param key        암호화에 사용할 키
     * @param plainBytes 암호화할 평문 바이트 배열
     * @return 암호화된 암호문 바이트 배열
     */
    byte @NotNull [] encrypt(@NotNull EntLibCryptoKey key, final byte[] plainBytes);

    /**
     * 암호문을 복호화하는 메소드입니다.
     *
     * @param key        복호화에 사용할 키
     * @param ciphertext 복호화할 암호문 바이트 배열
     * @return 복호화된 평문 바이트 배열
     */
    byte @NotNull [] decrypt(@NotNull EntLibCryptoKey key, final byte[] ciphertext);

}
