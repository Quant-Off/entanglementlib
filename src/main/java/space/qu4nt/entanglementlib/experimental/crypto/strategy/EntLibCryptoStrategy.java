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

import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibCryptoRegistry;

/// 암호화 스트레티지의 최상위 인터페이스입니다.
///
/// 모든 암호화 스트레티지(블록 암호, 스트림 암호, AEAD, 서명 등)는 이 인터페이스를 구현합니다.
/// [EntLibCryptoRegistry]에 등록되어 관리됩니다.
///
/// @author Q. T. Felix
/// @see CipherStrategy
/// @see SignatureStrategy
/// @since 1.1.0
public interface EntLibCryptoStrategy {

    /**
     * 이 스트레티지의 알고리즘 이름을 반환하는 메소드입니다.
     *
     * @return 알고리즘 이름
     */
    String getAlgorithmName();

    /**
     * 이 스트레티지의 알고리즘 타입을 반환하는 메소드입니다.
     *
     * @return 알고리즘 타입
     */
    EntLibAlgorithmType getAlgorithmType();

}
