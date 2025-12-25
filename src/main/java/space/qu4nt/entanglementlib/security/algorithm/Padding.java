/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;

@Getter
public enum Padding {

    PKCS5(CryptoMethod.SYMMETRIC, "PKCS5Padding"),
    ISO10126(CryptoMethod.SYMMETRIC, "ISO10126Padding"),
    ZERO_BYTE(CryptoMethod.SYMMETRIC, "ZeroBytePadding"),

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
