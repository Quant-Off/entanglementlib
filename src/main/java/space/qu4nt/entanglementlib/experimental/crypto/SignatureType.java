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

import lombok.Getter;

import static space.qu4nt.entanglementlib.experimental.crypto.CryptoFamily.*;

/// `BouncyCastle` 공급자 서비스 `Signature`에 포함된 전자 서명 알고리즘을 열거한 클래스입니다.
///
/// 이 열거형은 [EntLibAlgorithmType] 인터페이스를 구현하여 각 서명 알고리즘의
/// 패밀리, 키 크기, PQC(Post-Quantum Cryptography) 여부 등의 속성을 제공합니다.
///
/// @author Q. T. Felix
/// @see EntLibAlgorithmType
/// @see CryptoFamily
/// @since 1.1.0
@Getter
public enum SignatureType implements EntLibAlgorithmType {

    /**
     * ML-DSA-44 (NIST 보안 레벨 2) PQC 서명 알고리즘입니다.
     */
    ML_DSA_44(ML_DSA, 128, true),
    /**
     * ML-DSA-65 (NIST 보안 레벨 3) PQC 서명 알고리즘입니다.
     */
    ML_DSA_65(ML_DSA, 192, true),
    /**
     * ML-DSA-87 (NIST 보안 레벨 5) PQC 서명 알고리즘입니다.
     */
    ML_DSA_87(ML_DSA, 256, true),

    //
    // SLH-DSA bundle - start
    //
    SLH_DSA_SHA2_128s(SLH_DSA, 128, true),
    SLH_DSA_SHA2_128f(SLH_DSA, 128, true),
    SLH_DSA_SHA2_192s(SLH_DSA, 192, true),
    SLH_DSA_SHA2_192f(SLH_DSA, 192, true),
    SLH_DSA_SHA2_256s(SLH_DSA, 256, true),
    SLH_DSA_SHA2_256f(SLH_DSA, 256, true),
    SLH_DSA_SHAKE_128s(SLH_DSA, 128, true),
    SLH_DSA_SHAKE_128f(SLH_DSA, 128, true),
    SLH_DSA_SHAKE_192s(SLH_DSA, 192, true),
    SLH_DSA_SHAKE_192f(SLH_DSA, 192, true),
    SLH_DSA_SHAKE_256s(SLH_DSA, 256, true),
    SLH_DSA_SHAKE_256f(SLH_DSA, 256, true),
    //
    // SLH-DSA bundle - end
    //

    /**
     * RSA 2048비트 키 서명 알고리즘입니다.
     */
    RSA_2048(RSA, 2048, false),
    /**
     * RSA 4096비트 키 서명 알고리즘입니다.
     */
    RSA_4096(RSA, 4096, false),
    ;

    /**
     * 서명 알고리즘 패밀리입니다.
     */
    private final CryptoFamily family;

    /**
     * 서명 키의 비트 크기입니다.
     */
    private final int keySize;

    /**
     * PQC(Post-Quantum Cryptography) 알고리즘 여부입니다.
     */
    private final boolean pQC;

    /**
     * {@link SignatureType} 열거형 생성자입니다.
     *
     * @param family  서명 알고리즘 패밀리
     * @param keySize 키 크기 (비트 단위)
     * @param pQC     PQC 알고리즘 여부
     */
    SignatureType(CryptoFamily family, int keySize, boolean pQC) {
        this.family = family;
        this.keySize = keySize;
        this.pQC = pQC;
    }

    /**
     * 이 서명 알고리즘의 카테고리를 반환하는 메소드입니다.
     *
     * @return {@link EntLibCryptoCategory#SIGNATURE}
     */
    @Override
    public EntLibCryptoCategory getCategory() {
        return EntLibCryptoCategory.SIGNATURE;
    }

}
