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

/// 암호화 알고리즘 패밀리(종류별 분류)를 정의하는 열거형 클래스입니다.
///
/// 각 암호화 알고리즘이 속하는 패밀리를 분류하며, 대칭 키 암호, 비대칭 키 암호,
/// 스트림 암호, PQC(Post-Quantum Cryptography) 알고리즘 등을 포함합니다.
///
/// @author Q. T. Felix
/// @see EntLibAlgorithmType
/// @since 1.1.0
public enum CryptoFamily {

    /**
     * AES(Advanced Encryption Standard) 대칭 키 블록 암호 패밀리입니다.
     */
    AES,

    /**
     * DES(Data Encryption Standard) 대칭 키 블록 암호 패밀리입니다.
     */
    DES,

    /**
     * ChaCha 스트림 암호 패밀리입니다.
     */
    CHACHA,

    /**
     * RSA 비대칭 키 암호 패밀리입니다.
     */
    RSA,

    /**
     * SM2 중국 국가 표준 비대칭 키 암호 패밀리입니다.
     */
    SM2,

    /**
     * ARIA 대칭 키 블록 암호 패밀리입니다. (대한민국 국가 표준)
     */
    ARIA,

    /**
     * ML-DSA(Module-Lattice Digital Signature Algorithm) PQC 서명 알고리즘 패밀리입니다.
     */
    ML_DSA,

    /**
     * ML-KEM(Module-Lattice Key Encapsulation Mechanism) PQC 키 캡슐화 알고리즘 패밀리입니다.
     */
    ML_KEM,

    /**
     * SLH-DSA(Stateless Hash-based Digital Signature Algorithm) PQC 서명 알고리즘 패밀리입니다.
     */
    SLH_DSA

}
