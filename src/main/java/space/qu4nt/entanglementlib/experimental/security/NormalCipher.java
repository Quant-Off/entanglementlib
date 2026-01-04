/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.security.EntLibStreamingException;
import space.qu4nt.entanglementlib.experimental.security.builder.AEADAdditional;
import space.qu4nt.entanglementlib.experimental.security.builder.normalcipher.NormalCipherSetting;
import space.qu4nt.entanglementlib.experimental.security.builder.normalcipher.NormalCipherSettingResult;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.algorithm.StreamingCryptoService;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@Setter
@ApiStatus.Experimental
public final class NormalCipher extends EntLibAlgorithm<EntLibSecretKey> {

    public static final NormalCipher CHACHA20 = new NormalCipher("ChaCha20", 256, true, true, false);
    public static final NormalCipher CHACHA20_POLY1305 = new NormalCipher("ChaCha20", "ChaCha20-Poly1305", 256, true, true, false);

    private final boolean streaming;
    private String cipherAlgorithm;

    private NormalCipher(String keyGenerateAlgorithm, @Nullable String cipherAlgorithm, int keySize, boolean canAEAD, boolean streaming, boolean isPQC) {
        super(EntLibSecretKey.class, keyGenerateAlgorithm, keySize, canAEAD);
        this.streaming = streaming;
        this.cipherAlgorithm = cipherAlgorithm == null ? keyGenerateAlgorithm : cipherAlgorithm;
    }

    private NormalCipher(String keyGenerateAlgorithm, int keySize, boolean canAEAD, boolean streaming, boolean isPQC) {
        this(keyGenerateAlgorithm, null, keySize, canAEAD, streaming, isPQC);
    }

    public NormalCipherSetting.NormalCipherSettingBuilder normalCipherSetting() {
        return NormalCipherSetting.builder();
    }

    public static byte[] normalCipherEncrypt(@Nullable String provider,
                                             final byte[] plainBytes,
                                             final @NotNull NormalCipher normalCipher,
                                             EntLibSecretKey wrappedKey,
                                             @NotNull NormalCipherSettingResult normalCipherSettingResult,
                                             @Nullable AEADAdditional aeadAdditional,
                                             int chunkSize,
                                             @Nullable EntLibKey.CustomWiper<SecretKey> keyWiperCallback)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        // Validation
        final SecretKey key = Objects.requireNonNull(wrappedKey).getSecretKey();
        Objects.requireNonNull(normalCipherSettingResult);

        byte[] iv = Objects.requireNonNull(normalCipherSettingResult.getIv());
        byte[] aad = aeadAdditional == null ? null : aeadAdditional.getAad();

        // Cipher
        Cipher cipher;
        if (provider == null)
            cipher = Cipher.getInstance(Objects.requireNonNull(normalCipher.getCipherAlgorithm()));
        else
            cipher = Cipher.getInstance(Objects.requireNonNull(normalCipher.getCipherAlgorithm()), provider);

        IvParameterSpec mamboSpec = new IvParameterSpec(Objects.requireNonNull(iv));
        cipher.init(Cipher.ENCRYPT_MODE, key, mamboSpec);
        if (aad != null && aad.length > 0)
            cipher.updateAAD(aad);

        // Final
        if (chunkSize > 0 && plainBytes.length > chunkSize) {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                ByteArrayChunkProcessor.processInChunks(plainBytes, chunkSize, (data, offset, length) -> {
                    byte[] updatedBytes = cipher.update(data, offset, length);
                    if (updatedBytes != null)
                        outputStream.write(updatedBytes);
                });
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null)
                    outputStream.write(finalBytes);
                KeyDestroyHelper.zeroing(plainBytes);
                return outputStream.toByteArray();
            }
        }
        // NOTE: 이미 위에서 복사본이 할당된 상태이며, 아래와 같이 복사할 필요는 없음.
        //.      그래도 이 스코프 내에서 잔류하는 메모리 소거를 위해 추가함, 일관된 로직도 모두 같음.
        byte[] ciphertext = cipher.doFinal(plainBytes);
        final byte[] result = Arrays.copyOf(ciphertext, ciphertext.length);

        // Zeroing
        {
            KeyDestroyHelper.zeroing(ciphertext);
            KeyDestroyHelper.zeroing(plainBytes);
            wrappedKey.wipe(keyWiperCallback);
        }
        return result;
    }

    public static byte[] normalCipherDecrypt(@Nullable String provider,
                                             final byte[] ciphertext,
                                             final @NotNull NormalCipher normalCipher,
                                             EntLibSecretKey wrappedKey,
                                             @NotNull NormalCipherSettingResult normalCipherSettingResult,
                                             @Nullable AEADAdditional aeadAdditional,
                                             int chunkSize,
                                             @Nullable EntLibKey.CustomWiper<SecretKey> keyWiperCallback)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        // Validation
        final SecretKey key = Objects.requireNonNull(wrappedKey).getSecretKey();
        Objects.requireNonNull(normalCipherSettingResult);

        byte[] iv = Objects.requireNonNull(normalCipherSettingResult.getIv());
        byte[] aad = aeadAdditional == null ? null : aeadAdditional.getAad();

        // Cipher
        Cipher cipher;
        if (provider == null)
            cipher = Cipher.getInstance(Objects.requireNonNull(normalCipher.getCipherAlgorithm()));
        else
            cipher = Cipher.getInstance(Objects.requireNonNull(normalCipher.getCipherAlgorithm()), provider);

        IvParameterSpec mamboSpec = new IvParameterSpec(Objects.requireNonNull(iv));
        cipher.init(Cipher.DECRYPT_MODE, key, mamboSpec);
        if (aad != null && aad.length > 0)
            cipher.updateAAD(aad);

        // Final
        if (chunkSize > 0 && ciphertext.length > chunkSize) {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                ByteArrayChunkProcessor.processInChunks(ciphertext, chunkSize, (data, offset, length) -> {
                    byte[] updatedBytes = cipher.update(data, offset, length);
                    if (updatedBytes != null)
                        outputStream.write(updatedBytes);
                });
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null)
                    outputStream.write(finalBytes);
                KeyDestroyHelper.zeroing(ciphertext);
                // 이미 내부적으로 보안 복사 진행
                return outputStream.toByteArray();
            }
        }
        byte[] plainBytes = cipher.doFinal(ciphertext);
        final byte[] result = Arrays.copyOf(plainBytes, plainBytes.length);

        // Zeroing
        {
            KeyDestroyHelper.zeroing(plainBytes);
            KeyDestroyHelper.zeroing(ciphertext);
            wrappedKey.wipe(keyWiperCallback);
        }

        return result;
    }

    public static int encryptStream(@Nullable String provider,
                                    final @NotNull ByteBuffer inputBuffer,
                                    final @NotNull ByteBuffer outputBuffer,
                                    final @NotNull NormalCipher normalCipher,
                                    EntLibSecretKey wrappedKey,
                                    @NotNull NormalCipherSettingResult normalCipherSettingResult,
                                    @Nullable AEADAdditional aeadAdditional)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        final SecretKey key = Objects.requireNonNull(wrappedKey).getSecretKey();
        Objects.requireNonNull(normalCipherSettingResult);

        byte[] iv = Objects.requireNonNull(normalCipherSettingResult.getIv());
        byte[] aad = aeadAdditional == null ? null : aeadAdditional.getAad();

        // Cipher
        Cipher cipher;
        if (provider == null)
            cipher = Cipher.getInstance(Objects.requireNonNull(normalCipher.getCipherAlgorithm()));
        else
            cipher = Cipher.getInstance(Objects.requireNonNull(normalCipher.getCipherAlgorithm()), provider);

        IvParameterSpec mamboSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, mamboSpec);
        if (aad != null && aad.length > 0)
            cipher.updateAAD(aad);
        if (outputBuffer.remaining() < iv.length + inputBuffer.remaining())
            throw new EntLibStreamingException(StreamingCryptoService.class, "output-buffer-to-small-exc");
        outputBuffer.put(iv);
        int ciphertextLen = cipher.doFinal(inputBuffer, outputBuffer);
        return iv.length + ciphertextLen;
    }

    public static int decryptStream(@Nullable String provider,
                                    final @NotNull ByteBuffer inputBuffer,
                                    final @NotNull ByteBuffer outputBuffer,
                                    final @NotNull NormalCipher normalCipher,
                                    EntLibSecretKey wrappedKey,
                                    @NotNull NormalCipherSettingResult normalCipherSettingResult,
                                    @Nullable AEADAdditional aeadAdditional)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        final SecretKey key = Objects.requireNonNull(wrappedKey).getSecretKey();
        Objects.requireNonNull(normalCipherSettingResult);

        byte[] iv = Objects.requireNonNull(normalCipherSettingResult.getIv());
        byte[] aad = aeadAdditional == null ? null : aeadAdditional.getAad();

        if (inputBuffer.remaining() < iv.length)
            throw new IllegalBlockSizeException(LanguageInstanceBased.create(StreamingCryptoService.class).msg("not-enough-data-for-nonce-exc"));

        // Cipher
        Cipher cipher;
        if (provider == null)
            cipher = Cipher.getInstance(Objects.requireNonNull(normalCipher.getCipherAlgorithm()));
        else
            cipher = Cipher.getInstance(Objects.requireNonNull(normalCipher.getCipherAlgorithm()), provider);

        IvParameterSpec mamboSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, mamboSpec);
        if (aad != null && aad.length > 0)
            cipher.updateAAD(aad);
        return cipher.doFinal(inputBuffer, outputBuffer);
    }
}
