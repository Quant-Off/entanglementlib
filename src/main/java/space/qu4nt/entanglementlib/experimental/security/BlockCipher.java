/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.security;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.experimental.security.builder.AEADAdditional;
import space.qu4nt.entanglementlib.experimental.security.builder.blockcipher.BlockCipherSetting;
import space.qu4nt.entanglementlib.experimental.security.builder.blockcipher.BlockCipherSettingResult;
import space.qu4nt.entanglementlib.security.EntLibKey.CustomWiper;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.algorithm.Mode;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Objects;

@ApiStatus.Experimental
public final class BlockCipher extends EntLibAlgorithm<EntLibSecretKey> {

    // AES
    public static final BlockCipher AES128 = new BlockCipher("AES", true, 128);
    public static final BlockCipher AES192 = new BlockCipher("AES", true, 192);
    public static final BlockCipher AES256 = new BlockCipher("AES", true, 256);

    // 권장되지 않음
    public static final BlockCipher RC2      = new BlockCipher("RC2", false, 128);
    public static final BlockCipher DES      = new BlockCipher("DES", false, 56);
    public static final BlockCipher BLOWFISH = new BlockCipher("Blowfish", false, 256);

    private BlockCipher(String keyGenerateAlgorithm, boolean canAEAD, int keySize) {
        super(EntLibSecretKey.class, keyGenerateAlgorithm, keySize, canAEAD);
    }

    public BlockCipherSetting.BlockCipherSettingBuilder blockCipherSetting() {
        return BlockCipherSetting.builder().algorithm(this);
    }

    public static byte[] blockCipherEncrypt(@Nullable String provider,
                                            final byte[] plainBytes,
                                            EntLibSecretKey wrappedKey,
                                            @NotNull BlockCipherSettingResult blockCipherSettingResult,
                                            @Nullable AEADAdditional aeadAdditional,
                                            int chunkSize,
                                            @Nullable CustomWiper<SecretKey> keyWiperCallback)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, NoSuchProviderException {
        // Validation
        final SecretKey key = Objects.requireNonNull(wrappedKey).getSecretKey();
        Objects.requireNonNull(blockCipherSettingResult);

        Mode mode = blockCipherSettingResult.getMode();
        byte[] iv = blockCipherSettingResult.getIv();
        byte[] aad = aeadAdditional == null ? null : aeadAdditional.getAad();

        // Cipher
        Cipher cipher;
        if (provider == null)
            cipher = Cipher.getInstance(Objects.requireNonNull(blockCipherSettingResult.getFullName()));
        else
            cipher = Cipher.getInstance(Objects.requireNonNull(blockCipherSettingResult.getFullName()), provider);

        // blockcipher는 aes만 AEAD 지원
        if (blockCipherSettingResult.getFullName().contains("AES") && (mode.equals(Mode.AEAD_GCM) || mode.equals(Mode.AEAD_CCM))) { // AEAD
            GCMParameterSpec gcmMamboSpec = new GCMParameterSpec(128, Objects.requireNonNull(iv));
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmMamboSpec);
            if (aad != null && aad.length > 0)
                cipher.updateAAD(aad);
        } else if (mode.equals(Mode.CBC) || mode.equals(Mode.CFB) || mode.equals(Mode.OFB) || mode.equals(Mode.CTR)) { // Req iv
            IvParameterSpec mamboSpec = new IvParameterSpec(Objects.requireNonNull(iv));
            cipher.init(Cipher.ENCRYPT_MODE, key, mamboSpec);
        } else { // ECB (권장하지 않음)
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }

        // Final
        byte[] ciphertext;
        if (chunkSize > 0 && plainBytes.length > chunkSize) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayChunkProcessor.processInChunks(plainBytes, chunkSize, (data, offset, length) -> {
                byte[] updatedBytes = cipher.update(data, offset, length);
                if (updatedBytes != null)
                    outputStream.write(updatedBytes);
            });
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null)
                outputStream.write(finalBytes);
            ciphertext = outputStream.toByteArray();
        } else {
            ciphertext = cipher.doFinal(plainBytes);
        }
        final byte[] result = ciphertext.clone();

        // Zeroing
        {
            KeyDestroyHelper.zeroing(ciphertext);
            KeyDestroyHelper.zeroing(plainBytes);
            wrappedKey.wipe(keyWiperCallback);
        }
        return result;
    }

    public static byte[] blockCipherDecrypt(@Nullable String provider,
                                            final byte[] ciphertext,
                                            EntLibSecretKey wrappedKey,
                                            @NotNull BlockCipherSettingResult blockCipherSettingResult,
                                            @Nullable AEADAdditional aeadAdditional,
                                            int chunkSize,
                                            @Nullable CustomWiper<SecretKey> keyWiperCallback)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        // Validation
        final SecretKey key = Objects.requireNonNull(wrappedKey).getSecretKey();
        Objects.requireNonNull(blockCipherSettingResult);

        Mode mode = blockCipherSettingResult.getMode();
        byte[] iv = blockCipherSettingResult.getIv();
        byte[] aad = aeadAdditional == null ? null : aeadAdditional.getAad();

        // Cipher
        Cipher cipher;
        if (provider == null)
            cipher = Cipher.getInstance(Objects.requireNonNull(blockCipherSettingResult.getFullName()));
        else
            cipher = Cipher.getInstance(Objects.requireNonNull(blockCipherSettingResult.getFullName()), provider);

        if (mode.equals(Mode.AEAD_GCM) || mode.equals(Mode.AEAD_CCM)) { // AEAD
            GCMParameterSpec gcmMamboSpec = new GCMParameterSpec(128, Objects.requireNonNull(iv));
            cipher.init(Cipher.DECRYPT_MODE, key, gcmMamboSpec);
            if (aad != null && aad.length > 0)
                cipher.updateAAD(aad);
        } else if (mode.equals(Mode.CBC) || mode.equals(Mode.CFB) || mode.equals(Mode.OFB) || mode.equals(Mode.CTR)) { // Req iv
            IvParameterSpec mamboSpec = new IvParameterSpec(Objects.requireNonNull(iv));
            cipher.init(Cipher.DECRYPT_MODE, key, mamboSpec);
        } else { // ECB (권장하지 않음)
            cipher.init(Cipher.DECRYPT_MODE, key);
        }

        // Final
        if (chunkSize > 0 && ciphertext.length > chunkSize) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayChunkProcessor.processInChunks(ciphertext, chunkSize, (data, offset, length) -> {
                byte[] updatedBytes = cipher.update(data, offset, length);
                if (updatedBytes != null)
                    outputStream.write(updatedBytes);
            });
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null)
                outputStream.write(finalBytes);
            // 이미 내부적으로 보안 복사 진행
            return outputStream.toByteArray();
        }
        byte[] ready = cipher.doFinal(ciphertext);
        final byte[] result = Arrays.copyOf(ready, ready.length);

        KeyDestroyHelper.zeroing(ready);
        wrappedKey.wipe(keyWiperCallback);

        return result;
    }
}
