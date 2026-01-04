/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security;

import lombok.Getter;
import org.jetbrains.annotations.ApiStatus;

/**
 * kdf 등에 사용 가능한 {@code AlgorithmParameter}열거
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@ApiStatus.Experimental
public enum AlgorithmParameter {

    // SunJCE Pure
    AES,
    PBEWithSHA1AndRC4_128,
    PBEWithSHA1AndDESede,
    PBEWithSHA1AndRC4_40,
    PBEWithSHA1AndRC2_128,
    ChaCha20_Poly1305("ChaCha20-Poly1305"),
    PBEWithSHA1AndRC2_40,
    PBEWithMD5AndDES,
    OAEP,
    DESede,
    PBEWithHmacSHA224AndAES_128,
    PBES2,
    PBEWithHmacSHA224AndAES_256,
    PBEWithHmacSHA512AndAES_128,
    PBEWithHmacSHA512AndAES_256,
    PBEWithHmacSHA256AndAES_128,
    Blowfish,
    PBEWithHmacSHA256AndAES_256,
    PBEWithHmacSHA384AndAES_256,
    PBEWithHmacSHA512_256AndAES_256("PBEWithHmacSHA512/256AndAES_256"),
    PBEWithHmacSHA384AndAES_128,
    PBEWithHmacSHA1AndAES_128,
    DiffieHellman,
    PBEWithHmacSHA1AndAES_256,
    PBEWithHmacSHA512_256AndAES_128("PBEWithHmacSHA512/256AndAES_128"),
    RC2,
    PBEWithMD5AndTripleDES,
    PBEWithHmacSHA512_224AndAES_256("PBEWithHmacSHA512/224AndAES_256"),
    PBEWithHmacSHA512_224AndAES_128("PBEWithHmacSHA512/224AndAES_128"),
    DES,
    GCM,


    // BC Extension
    CAMELLIA,
    PSS,
    CHACHA7539,
    CAST6,
    CAST5,
    PKCS12PBE,
    BLOWFISH,
    RIJNDAEL,
    EC,
    ZUC_256("ZUC-256"),
    GOST28147,
    GOST3410,
    ECGOST3410,
    ECGOST3410_2012("ECGOST3410-2012"),
    PBKDF1,
    SKIPJACK,
    Threefish_256("Threefish-256"),
    ZUC_128("ZUC-128"),
    HC256,
    IDEA,
    Twofish,
    ELGAMAL,
    DSA,
    Serpent,
    ARIA,
    DH,
    NOEKEON,
    Shacal2,
    HC128;

    private final String name;

    AlgorithmParameter(String name) {
        this.name = name;
    }

    AlgorithmParameter() {
        this.name = name();
    }

    }
