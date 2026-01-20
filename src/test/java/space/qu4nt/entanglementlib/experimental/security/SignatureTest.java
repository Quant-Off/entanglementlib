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

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.EntanglementLibBootstrap;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

@Slf4j
class SignatureTest {

    @BeforeAll
    static void beforeAll() {
        EntanglementLibBootstrap.registerEntanglementLib("Test-123", true);
    }

    @Test
    @DisplayName("RSA 테스트")
    void rsaTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature rsa = Signature.RSA;

        EntLibKeyPair pair = rsa.keyGen();

        final byte[] plainBytes = "Hello, Secure World!".getBytes(StandardCharsets.UTF_8);

        byte[] signature = Signature.sign(
                rsa,
                null,
                plainBytes,
                pair, 0, null);

        log.info("Signature: {}", Hex.toHexString(signature));

        log.info("Verify: {}", Signature.verify(rsa,
                null,
                plainBytes,
                signature,
                pair, 0, null));
    }

    @Test
    @DisplayName("RSASSA-PSS 테스트")
    void rsaSsaPssTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature rsaSsaPss = Signature.RSASSA_PSS;

        EntLibKeyPair pair = rsaSsaPss.keyGen();

        final byte[] plainBytes = "Hello, Secure World!".getBytes(StandardCharsets.UTF_8);

        byte[] signature = Signature.sign(
                rsaSsaPss,
                null,
                plainBytes,
                pair, 0, null);

        log.info("Signature: {}", Hex.toHexString(signature));

        log.info("Verify: {}", Signature.verify(rsaSsaPss,
                null,
                plainBytes,
                signature,
                pair, 0, null));
    }
}