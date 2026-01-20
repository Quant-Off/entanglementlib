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
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.security.EntLibStreamingException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;

/**
 * ChaCha20 대칭키 스트리밍 알고리즘을 사용하기 위한 클래스입니다.
 * 불변 객체(String) 사용에 따른 메모리 잔류 취약점을 해결하기 위해 평문을 받지 않습니다.
 * <p>
 * 보안 강화를 위해 모든 바이트 배열 입출력에 대해 방어적 복사를 수행합니다.
 * <p>
 * {@link AutoCloseable}을 구현하여 작업 종료 시 평문, 개인 키를 즉시 영소거 및 파기합니다.
 * try-with-resources 블럭에서의 작업을 권장합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public final class ChaCha20 implements SymmetricCryptoService, StreamingCryptoService {

    private static final int DEF_COUNTER = 7;

    @Getter
    private final ClassicalType type = ClassicalType.CHACHA20;
    private byte[] plainBytes;

    private final byte[] nonce;

    private EntLibSecretKey key;
    private byte @Nullable [] ciphertext;

    @Getter
    @Setter
    @Nullable
    private Path encryptedOutput;
    @Getter
    @Setter
    @Nullable
    private Path decryptedOutput;

    private boolean closed = false;

    /**
     * ChaCha20 알고리즘에 사용되는 설정 정보를 담는 클래스입니다.
     * <p>
     * 암호화된 평문 데이터(암호문), {@code nonce} 바이트 배열, 청크 크기
     * 등의 설정 정보를 포함합니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    public static final class ChaCha20Setting {

        private final byte[] plainBytes;
        private final byte[] nonce;
        @Getter
        private final int chunkSize;

        @Getter
        @Setter
        @Nullable
        private Path encryptedOutput;
        @Getter
        @Setter
        @Nullable
        private Path decryptedOutput;

        @lombok.Builder
        public ChaCha20Setting(String plain, byte[] plainBytes, int nonceSize, int chunkSize, @Nullable Path encryptedOutput, @Nullable Path decryptedOutput) {
            if (plainBytes != null) {
                this.plainBytes = plainBytes.clone();
            } else if (plain != null) {
                this.plainBytes = plain.getBytes(StandardCharsets.UTF_8);
            } else {
                throw new EntLibAlgorithmSettingException(EntLibCryptoService.class, "plaintext-or-byte-array-exc");
            }
            this.nonce = new byte[nonceSize < 8 || nonceSize > 12 ? 12 : nonceSize];
            InternalFactory.getSafeRandom().nextBytes(nonce);
            this.chunkSize = chunkSize;
            this.encryptedOutput = encryptedOutput;
            this.decryptedOutput = decryptedOutput;
        }

        public byte[] getNonce() {
            return nonce.clone();
        }

        public byte[] getPlainBytes() {
            return plainBytes.clone();
        }

    }

    private ChaCha20(byte[] nonce, @NotNull String plain, @Nullable Path encryptedOutput, @Nullable Path decryptedOutput) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "ChaCha20"));
        this.nonce = nonce;
        this.plainBytes = plain.getBytes(StandardCharsets.UTF_8);
        this.encryptedOutput = encryptedOutput;
        this.decryptedOutput = decryptedOutput;
    }

    private ChaCha20(byte[] nonce, byte @NotNull [] plainBytes, @Nullable Path encryptedOutput, @Nullable Path decryptedOutput) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "ChaCha20"));
        this.nonce = nonce;
        this.plainBytes = Arrays.copyOf(plainBytes, plainBytes.length);
        this.encryptedOutput = encryptedOutput;
        this.decryptedOutput = decryptedOutput;
    }

    public static ChaCha20 create(byte[] nonce, @NotNull String plain) {
        return new ChaCha20(nonce, plain, null, null);
    }

    public static ChaCha20 create(byte[] nonce, byte @NotNull [] plainBytes) {
        return new ChaCha20(nonce, plainBytes, null, null);
    }

    public static ChaCha20 create(@NotNull ChaCha20.ChaCha20Setting chaCha20Setting) {
        return new ChaCha20(chaCha20Setting.getNonce(), chaCha20Setting.getPlainBytes(), chaCha20Setting.getEncryptedOutput(), chaCha20Setting.getDecryptedOutput());
    }

    @Override
    public @NotNull EntLibKeyPair generateEntKeyPair(@Nullable EntLibKey.CustomWiper<KeyPair> callback)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        throw new EntLibAlgorithmSettingException(EntLibCryptoService.class, "not-support-key-type-exc");
    }

    @Override
    public @NotNull EntLibSecretKey generateSecretKey(@Nullable EntLibKey.CustomWiper<SecretKey> callback) throws NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        this.key = InternalFactory.Key.secretKeygen(type.getAlgorithmName(), 256, null);
        return key;
    }

    public byte @NotNull [] getPlainBytes() {
        checkClosed();
        return plainBytes.clone();
    }

    public byte @NotNull [] getCiphertext() {
        checkClosed();
        return this.ciphertext == null ? new byte[1] : ciphertext.clone();
    }

    @Override
    public byte[] encrypt(@NotNull SecretKey secretKey, byte @NotNull [] plainBytes, byte @Nullable [] iv, byte[] aad, int chunkSize)
            throws Exception {
        checkClosed();
        Cipher cipher = Cipher.getInstance(type.getAlgorithmName());
        ChaCha20ParameterSpec mamboSpec = new ChaCha20ParameterSpec(nonce, DEF_COUNTER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, mamboSpec);

        if (chunkSize > 0 && plainBytes.length > chunkSize) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayChunkProcessor.processInChunks(plainBytes, chunkSize, (data, offset, length) -> {
                byte[] updatedBytes = cipher.update(data, offset, length);
                if (updatedBytes != null) {
                    outputStream.write(updatedBytes);
                }
            });
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) {
                outputStream.write(finalBytes);
            }
            this.ciphertext = outputStream.toByteArray();
        } else {
            this.ciphertext = cipher.doFinal(plainBytes);
        }
        return this.ciphertext.clone();
    }

    @Override
    public byte[] decrypt(@NotNull SecretKey secretKey, byte @NotNull [] cipherBytes, byte @Nullable [] iv, byte[] aad, int chunkSize)
            throws Exception {
        checkClosed();
        Cipher cipher = Cipher.getInstance(type.getAlgorithmName());
        ChaCha20ParameterSpec mamboSpec = new ChaCha20ParameterSpec(nonce, DEF_COUNTER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, mamboSpec);

        if (chunkSize > 0 && cipherBytes.length > chunkSize) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayChunkProcessor.processInChunks(cipherBytes, chunkSize, (data, offset, length) -> {
                byte[] updatedBytes = cipher.update(data, offset, length);
                if (updatedBytes != null) {
                    outputStream.write(updatedBytes);
                }
            });
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) {
                outputStream.write(finalBytes);
            }
            return outputStream.toByteArray();
        } else {
            return cipher.doFinal(cipherBytes);
        }
    }

    @Override
    public int encryptStream(@NotNull SecretKey secretKey,
                             @NotNull ByteBuffer inputBuffer,
                             @NotNull ByteBuffer outputBuffer)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException, ShortBufferException {
        checkClosed();
        // JEP 329 + bytebuffer streaming
        Cipher cipher = Cipher.getInstance(type.getAlgorithmName());
        ChaCha20ParameterSpec mamboSpec = new ChaCha20ParameterSpec(nonce, DEF_COUNTER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, mamboSpec);
        if (outputBuffer.remaining() < nonce.length + inputBuffer.remaining())
            throw new EntLibStreamingException(StreamingCryptoService.class, "output-buffer-to-small-exc");
        outputBuffer.put(nonce);
        int ciphertextLen = cipher.doFinal(inputBuffer, outputBuffer);
        return nonce.length + ciphertextLen;
    }

    @Override
    public int decryptStream(@NotNull SecretKey secretKey,
                             @NotNull ByteBuffer inputBuffer,
                             @NotNull ByteBuffer outputBuffer)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        checkClosed();
        if (inputBuffer.remaining() < nonce.length)
            throw new IllegalBlockSizeException(LanguageInstanceBased.create(StreamingCryptoService.class).msg("not-enough-data-for-nonce-exc"));
        byte[] nonce = new byte[this.nonce.length];
        inputBuffer.get(nonce);
        Cipher cipher = Cipher.getInstance(type.getAlgorithmName());
        ChaCha20ParameterSpec mamboSpec = new ChaCha20ParameterSpec(nonce, DEF_COUNTER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, mamboSpec);
        return cipher.doFinal(inputBuffer, outputBuffer);
    }

    public void close() throws Exception {
        if (closed) return;

        if (plainBytes != null) {
            KeyDestroyHelper.zeroing(plainBytes);
            log.debug(LanguageInstanceBased.create(StreamingCryptoService.class)
                    .argsNonTopKey("debug-plain-bytes-zeroing-result", Hex.toHexString(plainBytes)));
            plainBytes = null;
        }

        if (key != null) {
            try {
                KeyDestroyHelper.destroy(key);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            key = null;
        }
        closed = true;
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class).argsNonTopKey("debug-instance-closed", "ChaCha20"));
    }

    private void checkClosed() {
        if (closed) {
            throw new EntLibSecureIllegalStateException(EntLibCryptoService.class, "data-already-destroyed-exc", "ChaCha20");
        }
    }
}
