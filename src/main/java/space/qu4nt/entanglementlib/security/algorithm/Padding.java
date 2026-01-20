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

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;

@Getter
public enum Padding {

    PKCS5(CryptoMethod.SYMMETRIC, "PKCS5Padding"),
    /**
     * {@link #PKCS5} 와 근본적으로는 동일하지만 차별화
     */
    PKCS7(CryptoMethod.SYMMETRIC, "PKCS7Padding"),
    ISO7816(CryptoMethod.SYMMETRIC, "ISO7816Padding"),
    ISO10126(CryptoMethod.SYMMETRIC, "ISO10126Padding"),
    ZERO_BYTE(CryptoMethod.SYMMETRIC, "ZeroBytePadding"),

    /**
     * {@link #PKCS5} 와 근본적으로 다름
     */
    PKCS1(CryptoMethod.ASYMMETRIC, "PKCS1Padding"),
    OAEP_AND_MGF1(CryptoMethod.ASYMMETRIC, "OAEPWith{digest}AndMGF1Padding"),

    NO("NoPadding"),
    ;

    private final CryptoMethod type;
    private final String name;

    Padding(String name) {
        this(null, name);
    }

    Padding(CryptoMethod type, String name) {
        this.type = type;
        this.name = name;
    }
}
