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

package space.qu4nt.entanglementlib.experimental.crypto.strategy.detail;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.key.EntLibCryptoKey;
import space.qu4nt.entanglementlib.experimental.crypto.key.strategy.detail.ChaCha20SymmetricKeyStrategy;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.StreamCipherStrategy;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.io.EntFile;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.function.BiConsumer;

/// ChaCha20 스트림 암호 알고리즘 전략 클래스입니다.
///
/// ChaCha20은 AES의 대안으로 사용되는 고속 스트림 암호 알고리즘입니다.
/// BouncyCastle의 [ChaChaEngine]을 사용하여 암호화/복호화를 수행합니다.
///
/// 스트림 암호화는 [EntFile#byteBufferStreaming(Path, Path, int, int, BiConsumer)]
/// 메소드를 사용하여 대용량 파일을 효율적으로 처리할 수 있습니다.
/// IV(Nonce) 길이는 8바이트(64비트)를 사용합니다.
///
/// 키는 네이티브 메모리에서 관리되며, 사용 후 즉시 소거됩니다.
///
/// @author Q. T. Felix
/// @see AbstractStreamCipher
/// @see StreamCipherStrategy
/// @see CipherType#CHACHA20
/// @since 1.1.0
@Slf4j
public final class ChaCha20Strategy extends AbstractStreamCipher {

    /**
     * ChaCha20Strategy 생성자입니다.
     *
     * @param base ChaCha20 암호화 타입 ({@link CipherType#CHACHA20})
     */
    ChaCha20Strategy(@NotNull CipherType base) {
        super(base, new ChaChaEngine());
    }

    /**
     * 입력 버퍼의 데이터를 스트리밍 방식으로 암호화하여 출력 버퍼에 쓰는 메소드입니다.
     * <p>
     * 출력 버퍼는 입력 데이터 크기에 8바이트(IV) 이상의 여유 공간이 필요합니다.
     *
     * @param key          암호화에 사용할 키
     * @param inputBuffer  암호화할 데이터가 담긴 입력 버퍼
     * @param outputBuffer 암호화된 데이터를 쓸 출력 버퍼
     * @return 처리된 바이트 수
     * @throws StackOverflowError 출력 버퍼가 너무 작은 경우
     */
    @Override
    public int streamEncrypt(@NotNull EntLibCryptoKey key, @NotNull ByteBuffer inputBuffer, @NotNull ByteBuffer outputBuffer) {
        if (outputBuffer.remaining() < 8 + inputBuffer.remaining())
            throw new StackOverflowError("Output buffer is too small!");
        byte[] input = new byte[inputBuffer.remaining()];
        inputBuffer.get(input);
        byte[] output = encrypt(key, input);
        outputBuffer.put(output);
        return output.length;
    }

    /**
     * 입력 버퍼의 데이터를 스트리밍 방식으로 복호화하여 출력 버퍼에 쓰는 메소드입니다.
     * <p>
     * 입력 버퍼는 최소 8바이트(IV) 이상의 데이터를 포함해야 합니다.
     *
     * @param key          복호화에 사용할 키
     * @param inputBuffer  복호화할 데이터가 담긴 입력 버퍼
     * @param outputBuffer 복호화된 데이터를 쓸 출력 버퍼
     * @return 처리된 바이트 수
     * @throws StackOverflowError 입력 버퍼가 너무 작은 경우
     */
    @Override
    public int streamDecrypt(@NotNull EntLibCryptoKey key, @NotNull ByteBuffer inputBuffer, @NotNull ByteBuffer outputBuffer) {
        if (inputBuffer.remaining() < 8)
            throw new StackOverflowError("Input buffer is too small!");
        byte[] input = new byte[inputBuffer.remaining()];
        inputBuffer.get(input);
        byte[] output = decrypt(key, input);
        outputBuffer.put(output);
        return output.length;
    }

    /**
     * 평문을 ChaCha20 알고리즘으로 암호화하는 메소드입니다.
     * <p>
     * 8바이트의 Nonce(IV)가 자동으로 생성되며,
     * 결과는 {@code IV + CipherText} 형식으로 반환됩니다.
     *
     * @param key        암호화에 사용할 키
     * @param plainBytes 암호화할 평문 바이트 배열
     * @return 암호화된 바이트 배열 (IV + CipherText)
     * @throws RuntimeException 키가 {@code null}인 경우
     */
    @Override
    public byte @NotNull [] encrypt(@NotNull EntLibCryptoKey key, byte[] plainBytes) {
        // ChaCha20은 8바이트(64비트) 또는 12바이트(96비트) Nonce(IV)를 사용합니다.
        // 여기서는 일반적인 8바이트 Nonce를 사용합니다.
        byte[] iv = EntLibKey.generateSafeRandomBytes(8);

        // 네이티브 메모리에서 키 바이트 배열 추출
        byte[] keyBytes = key.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");

        ParametersWithIV params = new ParametersWithIV(new KeyParameter(keyBytes), iv);

        // 사용 후 힙에 복사된 키 바이트 즉시 소거
        KeyDestroyHelper.zeroing(keyBytes);

        byte[] output = new byte[plainBytes.length];
        processStreamCipher(true, params, plainBytes, 0, plainBytes.length, output, 0);

        // 결과 반환: IV + CipherText
        byte[] result = new byte[iv.length + output.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(output, 0, result, iv.length, output.length);

        return result;
    }

    /**
     * 암호문을 ChaCha20 알고리즘으로 복호화하는 메소드입니다.
     * <p>
     * 입력된 암호문에서 8바이트의 IV를 추출하여 복호화를 수행합니다.
     *
     * @param key        복호화에 사용할 키
     * @param ciphertext 복호화할 암호문 바이트 배열 (IV + CipherText)
     * @return 복호화된 평문 바이트 배열
     * @throws IllegalArgumentException 암호문이 IV(8바이트)보다 짧은 경우
     * @throws RuntimeException         키가 {@code null}인 경우
     */
    @Override
    public byte @NotNull [] decrypt(@NotNull EntLibCryptoKey key, byte[] ciphertext) {
        if (ciphertext.length < 8) {
            throw new IllegalArgumentException("Ciphertext too short to contain IV");
        }

        byte[] iv = new byte[8];
        System.arraycopy(ciphertext, 0, iv, 0, 8);

        byte[] actualCiphertext = new byte[ciphertext.length - 8];
        System.arraycopy(ciphertext, 8, actualCiphertext, 0, actualCiphertext.length);

        // 네이티브 메모리에서 키 바이트 배열 추출
        byte[] keyBytes = key.toByteArray();
        if (keyBytes == null)
            throw new RuntimeException("key null");

        ParametersWithIV params = new ParametersWithIV(new KeyParameter(keyBytes), iv);

        // 사용 후 힙에 복사된 키 바이트 즉시 소거
        KeyDestroyHelper.zeroing(keyBytes);

        byte[] output = new byte[actualCiphertext.length];
        processStreamCipher(false, params, actualCiphertext, 0, actualCiphertext.length, output, 0);

        return output;
    }

    /**
     * 알고리즘 이름을 반환하는 메소드입니다.
     *
     * @return 알고리즘 이름 "ChaCha20"
     */
    @Override
    public String getAlgorithmName() {
        return "ChaCha20";
    }

    // 테스트용 psvm
    public static void main(String[] args) {
        byte[] plain = "Hello, ChaCha20 Secure World!".getBytes(StandardCharsets.UTF_8);

        ChaCha20Strategy chaCha20Strategy = new ChaCha20Strategy(CipherType.CHACHA20);

        ChaCha20SymmetricKeyStrategy keyStrategy = ChaCha20SymmetricKeyStrategy.create(chaCha20Strategy);

        try (EntLibCryptoKey key = keyStrategy.generateKey()) {
            // 키 확인 (테스트용 - 실제 운영 환경에서는 키를 로그에 찍으면 안 됨)
            MemorySegment keySegment = key.getKeySegment();
            byte[] keyBytes = keySegment.toArray(ValueLayout.JAVA_BYTE);
            log.info("Key (Hex): {}", Hex.toHexString(keyBytes));
            KeyDestroyHelper.zeroing(keyBytes); // 확인 후 즉시 소거
            {
                // 암호화
                byte[] encrypted = chaCha20Strategy.encrypt(key, plain);
                log.info("Normal Encrypted: {}", Hex.toHexString(encrypted));

                // 복호화
                byte[] decrypted = chaCha20Strategy.decrypt(key, encrypted);
                log.info("Normal Decrypted: {}", Hex.toHexString(decrypted));
                log.info("Normal Decrypted Plain: {}", new String(decrypted, StandardCharsets.UTF_8));
            } // Normal Cipher

            {
                Path input = Path.of(InternalFactory.envEntanglementPublicDir(), "CHACHATestInput.json");
                Path output = Path.of(InternalFactory.envEntanglementPublicDir(), "CHACHATestOutput.json");
                Path decOutput = Path.of(InternalFactory.envEntanglementPublicDir(), "CHACHATestDecrypted.json");
                EntFile.byteBufferStreaming(input, output, 1024, 1024, (i, o) ->
                        chaCha20Strategy.streamEncrypt(key, i, o));

                EntFile.byteBufferStreaming(output, decOutput, 1024, 1024, (i, o) ->
                        chaCha20Strategy.streamDecrypt(key, i, o));
            } // Stream Cipher
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
