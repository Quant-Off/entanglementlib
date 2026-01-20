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

    private final String name = toLowerCase(replace(name(), "_", "-"));

}
