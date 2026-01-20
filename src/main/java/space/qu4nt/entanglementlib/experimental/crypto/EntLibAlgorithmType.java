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

package space.qu4nt.entanglementlib.experimental.crypto;

/// 암호화 알고리즘의 공통 속성을 정의하는 인터페이스입니다.
///
/// 모든 암호화 알고리즘 타입([CipherType], [SignatureType] 등)은
/// 이 인터페이스를 구현하여 알고리즘의 카테고리, 패밀리, 키 크기, PQC 여부 등의
/// 속성을 제공합니다.
///
/// @author Q. T. Felix
/// @see CipherType
/// @see SignatureType
/// @see EntLibCryptoCategory
/// @see CryptoFamily
/// @since 1.1.0
public interface EntLibAlgorithmType {

    /**
     * 이 알고리즘의 카테고리를 반환하는 메소드입니다.
     *
     * @return 알고리즘 카테고리 (암호화, 서명, 키 합의 등)
     */
    EntLibCryptoCategory getCategory();

    /**
     * 이 알고리즘이 속하는 패밀리를 반환하는 메소드입니다.
     *
     * @return 알고리즘 패밀리 (AES, RSA, ML-DSA 등)
     */
    CryptoFamily getFamily();

    /**
     * 이 알고리즘의 키 크기를 비트 단위로 반환하는 메소드입니다.
     *
     * @return 키 크기 (비트 단위)
     */
    int getKeySize();

    /**
     * 이 알고리즘이 PQC(Post-Quantum Cryptography) 알고리즘인지 여부를 반환하는 메소드입니다.
     *
     * @return PQC 알고리즘이면 {@code true}, 아니면 {@code false}
     */
    boolean isPQC();

}
