/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto;

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
