/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security;

import lombok.Getter;
import org.jetbrains.annotations.ApiStatus;

import static space.qu4nt.entanglementlib.util.StringUtil.replace;
import static space.qu4nt.entanglementlib.util.StringUtil.toLowerCase;

@Getter
@ApiStatus.Experimental
public enum ECParameter {

    secp256r1,
    secp384r1,
    secp521r1,

    brainpoolP512t1,
    brainpoolP512r1,
    brainpoolP384t1,
    brainpoolP384r1,
    brainpoolP320t1,
    sect571r1,
    brainpoolP320r1,
    sect571k1,
    brainpoolP256t1,
    sect409r1,
    brainpoolP256r1,
    brainpoolP224t1,
    sect409k1,
    brainpoolP224r1,
    brainpoolP192t1,
    brainpoolP192r1,
    secp224r1,
    brainpoolP160t1,
    secp224k1,
    brainpoolP160r1,
    secp192k1,
    secp160r2,
    GostR3410_2001_CryptoPro_XchB,
    wapip192v1,
    GostR3410_2001_CryptoPro_XchA,
    GostR3410_2001_CryptoPro_C,
    GostR3410_2001_CryptoPro_B,
    GostR3410_2001_CryptoPro_A,
    secp192r1,
    secp128r2,
    secp160k1,
    secp128r1,
    secp160r1,
    sect233r1,
    secp112r2,
    sect233k1,
    secp112r1,
    sect193r2,
    sect113r2,
    sect193r1,
    sect113r1,
    sect131r2,
    sect239k1,
    sect131r1,
    sect163r1,
    sect163k1,
    wapi192v1,
    sm2p256v1,
    sect283r1,
    sect283k1,
    sect163r2,
    secp256k1,
    FRP256v1;

    private String name = toLowerCase(replace(name(), "_", "-"));

}
