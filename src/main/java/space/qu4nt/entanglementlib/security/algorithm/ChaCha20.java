/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
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
import space.qu4nt.entanglementlib.security.EntKeyPair;
import space.qu4nt.entanglementlib.security.EntLibParameterSpec;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public final class ChaCha20 implements SymmetricCryptoService, StreamingCryptoService {

    private static final LanguageInstanceBased<ChaCha20> lang = LanguageInstanceBased.create(ChaCha20.class);
    private static final int DEF_COUNTER = 7;

    private final ClassicalType type = ClassicalType.CHACHA20;
    private byte[] plainBytes;

    private final byte[] nonce;

    private SecretKey key;
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
        @Getter
        private final ClassicalType type;
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
            this.type = ClassicalType.CHACHA20;
            this.nonce = new byte[nonceSize < 8 || nonceSize > 12 ? 12 : nonceSize];
            InternalFactory.SAFE_RANDOM.nextBytes(nonce);
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
        log.debug(lang.setClass(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "ChaCha20"));
        this.nonce = nonce;
        this.plainBytes = plain.getBytes(StandardCharsets.UTF_8);
        this.encryptedOutput = encryptedOutput;
        this.decryptedOutput = decryptedOutput;
    }

    private ChaCha20(byte[] nonce, byte @NotNull [] plainBytes, @Nullable Path encryptedOutput, @Nullable Path decryptedOutput) {
        log.debug(lang.setClass(EntLibCryptoService.class)
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
    public @NotNull EntKeyPair generateEntKeyPair()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        throw new EntLibAlgorithmSettingException(EntLibCryptoService.class, "not-support-key-type-exc");
    }

    @Override
    public @NotNull SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        checkClosed();
        this.key = InternalFactory.Key.secretKeygen(type.getAlgorithmName(), 256);
        return key;
    }

    @Override
    public byte @NotNull [] getPlainBytes() {
        checkClosed();
        return plainBytes.clone();
    }

    @Override
    public EntLibParameterSpec getType() {
        return ClassicalType.CHACHA20;
    }

    public byte @NotNull [] getCiphertext() {
        checkClosed();
        return this.ciphertext == null ? new byte[1] : ciphertext.clone();
    }

    @Override
    public byte[] encrypt(@NotNull SecretKey secretKey, byte @NotNull [] plainBytes, @Nullable Padding padding, int chunkSize)
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

    public byte[] encrypt(@NotNull SecretKey secretKey, byte @NotNull [] plainBytes, int chunkSize)
            throws Exception {
        return encrypt(secretKey, plainBytes, null, chunkSize);
    }

    @Override
    public byte[] decrypt(@NotNull SecretKey secretKey, byte @NotNull [] cipherBytes, @Nullable Padding padding, int chunkSize)
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

    public byte[] decrypt(@NotNull SecretKey secretKey, byte @NotNull [] cipherBytes, int chunkSize)
            throws Exception {
        return decrypt(secretKey, cipherBytes, null, chunkSize);
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

    @Override
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
