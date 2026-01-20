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

/// `BouncyCastle` 공급자 서비스 `Cipher`에 포함된 암호화 알고리즘을 열거한 클래스입니다.
///
/// 이 열거형은 [EntLibAlgorithmType] 인터페이스를 구현하여 각 암호화 알고리즘의
/// 패밀리, 키 크기, PQC(Post-Quantum Cryptography) 여부 등의 속성을 제공합니다.
///
/// @author Q. T. Felix
/// @see EntLibAlgorithmType
/// @see CryptoFamily
/// @since 1.1.0
@Getter
public enum CipherType implements EntLibAlgorithmType {

    /**
     * AES 128비트 키 암호화 알고리즘입니다.
     */
    AES_128(AES, 128, false),
    /**
     * AES 192비트 키 암호화 알고리즘입니다.
     */
    AES_192(AES, 192, false),
    /**
     * AES 256비트 키 암호화 알고리즘입니다.
     */
    AES_256(AES, 256, false),

    /**
     * Triple DES 128비트 키 암호화 알고리즘입니다.
     */
    DESede_128(DES, 128, false),
    /**
     * Triple DES 168비트 키 암호화 알고리즘입니다.
     */
    DESede_168(DES, 168, false),
    /**
     * Triple DES 192비트 키 암호화 알고리즘입니다.
     */
    DESede_192(DES, 192, false),

    /**
     * ChaCha20 스트림 암호화 알고리즘입니다.
     */
    CHACHA20(CHACHA, 256, false),
    /**
     * ChaCha20-Poly1305 AEAD 암호화 알고리즘입니다.
     */
    CHACHA20_POLY1305(CHACHA, 256, false),

    /**
     * RSA 2048비트 키 암호화 알고리즘입니다.
     */
    RSA_2048(RSA, 2048, false),
    /**
     * RSA 4096비트 키 암호화 알고리즘입니다.
     */
    RSA_4096(RSA, 4096, false),

    /**
     * SM2 with SHA-224 암호화 알고리즘입니다.
     */
    SM2withSHA224(SM2, 256, false),
    /**
     * SM2 with SHA-256 암호화 알고리즘입니다.
     */
    SM2withSHA256(SM2, 256, false),
    /**
     * SM2 with SHA-384 암호화 알고리즘입니다.
     */
    SM2withSHA384(SM2, 256, false),
    /**
     * SM2 with SHA-512 암호화 알고리즘입니다.
     */
    SM2withSHA512(SM2, 256, false),

    /**
     * ARIA 128비트 키 암호화 알고리즘입니다.
     */
    ARIA_128(ARIA, 128, false),
    /**
     * ARIA 192비트 키 암호화 알고리즘입니다.
     */
    ARIA_192(ARIA, 192, false),
    /**
     * ARIA 256비트 키 암호화 알고리즘입니다.
     */
    ARIA_256(ARIA, 256, false),
    ;

    /**
     * 암호화 알고리즘 패밀리입니다.
     */
    private final CryptoFamily family;

    /**
     * 암호화 키의 비트 크기입니다.
     */
    private final int keySize;

    /**
     * PQC(Post-Quantum Cryptography) 알고리즘 여부입니다.
     */
    private final boolean pQC;

    /**
     * {@link CipherType} 열거형 생성자입니다.
     *
     * @param family  암호화 알고리즘 패밀리
     * @param keySize 키 크기 (비트 단위)
     * @param pQC     PQC 알고리즘 여부
     */
    CipherType(CryptoFamily family, int keySize, boolean pQC) {
        this.family = family;
        this.keySize = keySize;
        this.pQC = pQC;
    }

    /**
     * 이 암호화 알고리즘의 카테고리를 반환하는 메소드입니다.
     *
     * @return {@link EntLibCryptoCategory#CIPHER}
     */
    @Override
    public EntLibCryptoCategory getCategory() {
        return EntLibCryptoCategory.CIPHER;
    }

}
