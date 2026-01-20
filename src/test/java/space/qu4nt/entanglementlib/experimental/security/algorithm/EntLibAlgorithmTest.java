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

package space.qu4nt.entanglementlib.experimental.security.algorithm;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.EntanglementLibBootstrap;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.security.BlockCipher;
import space.qu4nt.entanglementlib.experimental.security.Signature;
import space.qu4nt.entanglementlib.experimental.security.builder.AEADAdditional;
import space.qu4nt.entanglementlib.experimental.security.builder.blockcipher.BlockCipherSetting;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.security.algorithm.Padding;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

@Slf4j
class EntLibAlgorithmTest {

    @BeforeAll
    static void beforeAll() {
        EntanglementLibBootstrap.registerEntanglementLib("Test-123", true);
    }

    @Test
    @DisplayName("AES 테스트")
    void blockCipherTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException {
        BlockCipher aes256 = BlockCipher.AES256;

        final EntLibSecretKey key = aes256.keyGen();

        final BlockCipherSetting result = aes256.blockCipherSetting()
                .mode(Mode.CBC)
                .padding(Padding.PKCS5)
                .done();

        final AEADAdditional aeadAdditional = aes256.aeadAdditional("This is Awesome!".getBytes(StandardCharsets.UTF_8));

        byte[] enc = BlockCipher.blockCipherEncrypt(
                null,
                "AES256!!!".getBytes(StandardCharsets.UTF_8),
                key,
                result,
                aeadAdditional,
                0,
                null);

        log.info("Enc: {}", Hex.toHexString(enc));
    }

    @Test
    @DisplayName("전자 서명 ML-DSA 테스트")
    void signatureTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        Signature mldsa65 = Signature.ML_DSA_65;

        final EntLibKeyPair pair = mldsa65.keyGen(InternalFactory.getBCNormalProvider());


    }

}