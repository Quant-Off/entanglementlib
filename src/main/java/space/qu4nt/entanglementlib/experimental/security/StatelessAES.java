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

import com.quant.quantregular.annotations.QuantTypeOwner;
import com.quant.quantregular.annotations.Quanters;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.algorithm.*;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * 기존 고급 암호화 표준(Advanced Encryption Standard, AES) 알고리즘을 제공하던
 * {@link AES} 클래스는 상태를 가지기 때문에 메모리 과다 점유(Double/Triple Buffering)
 * 문제를 해결하기 위해 설계를 변경해야 했습니다. 다만 얽힘 라이브러리에서 알고리즘 클래스가 상태를 가지게 되면
 * 반드시 평문, 키 등의 데이터를 인스턴스에 보관해야 하기 때문에 대안으로 만들어진 상태 없는(stateless) 클래스입니다.
 * <p>
 * 상태를 떠나 알고리즘 클래스의 암/복호화, 서명, 캡슐화 등의 로직은 조만간 팩토리에서 실행되도록 수정될 것입니다만,
 * 세부적인 캡슐화의 기능을 상실할 가능성과 그 대안을 결정하기 전 까진 실험적 기능으로 차별해두고자 합니다.
 * <p>
 * 추 후 이 작업의 효율성이 좋다고 판단될 경우, 기존 알고리즘 클래스는 제거되거나 거의 변경될 수 있습니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@QuantTypeOwner(Quanters.Q_T_FELIX)
@ApiStatus.Experimental
@Slf4j
public final class StatelessAES {

    public static byte @NotNull [] encrypt(final @NotNull ClassicalType type,
                                           byte @NotNull [] plainBytes,
                                           @NotNull SecretKey key,
                                           final @NotNull Mode mode,
                                           final @NotNull Padding padding,
                                           byte @NotNull [] iv,
                                           byte @Nullable [] aad,
                                           int chunkSize)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Objects.requireNonNull(plainBytes);
        Objects.requireNonNull(key);
        if (Objects.requireNonNull(iv).length != 12 && Objects.requireNonNull(iv).length != 16)
            throw new EntLibSecureIllegalArgumentException(SymmetricCryptoService.class, "invalid-iv-exc");

        if (mode.equals(Mode.ECB)) {
            log.warn(LanguageInstanceBased.create(SymmetricCryptoService.class).msg("not-recommended-ecb"));
        }

        final Cipher cipher = Cipher.getInstance(Mode.getFullName(type.getAlgorithmName(), mode, padding));
        if (mode.isAead()) { // AEAD
            GCMParameterSpec gcmMamboSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmMamboSpec);
            if (aad != null && aad.length > 0)
                cipher.updateAAD(aad);
        } else if (mode.equals(Mode.CBC) || mode.equals(Mode.CFB) || mode.equals(Mode.OFB) || mode.equals(Mode.CTR)) { // Req iv
            IvParameterSpec mamboSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, mamboSpec);
        } else { // ECB (권장하지 않음)
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }

        byte[] ciphertext;
        if (chunkSize > 0 && plainBytes.length > chunkSize) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayChunkProcessor.processInChunks(plainBytes, chunkSize, (data, offset, length) -> {
                byte[] updatedBytes = cipher.update(data, offset, length);
                if (updatedBytes != null) {
                    outputStream.write(updatedBytes);
                }
            });
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null)
                outputStream.write(finalBytes);
            ciphertext = outputStream.toByteArray();
        } else {
            ciphertext = cipher.doFinal(plainBytes);
        }
        return ciphertext.clone();
    }

    public static byte @NotNull [] encrypt(final @NotNull ClassicalType type,
                                           byte @NotNull [] plainBytes,
                                           final byte @NotNull [] customKeyBytes,
                                           final @NotNull Mode mode,
                                           final @NotNull Padding padding,
                                           byte @NotNull [] iv,
                                           byte @Nullable [] aad,
                                           int chunkSize)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        return encrypt(type, plainBytes, new SecretKeySpec(customKeyBytes, "AES"), mode, padding, iv, aad, chunkSize);
    }

    public static byte @NotNull [] decrypt(final @NotNull ClassicalType type,
                                           byte @NotNull [] cipherBytes,
                                           @NotNull SecretKey key,
                                           final @NotNull Mode mode,
                                           final @NotNull Padding padding,
                                           byte @NotNull [] iv,
                                           byte @Nullable [] aad,
                                           int chunkSize)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Objects.requireNonNull(cipherBytes);
        Objects.requireNonNull(key);

        if (mode.equals(Mode.ECB)) {
            log.warn(LanguageInstanceBased.create(SymmetricCryptoService.class).msg("not-recommended-ecb"));
        }

        final Cipher cipher = Cipher.getInstance(Mode.getFullName(type.getAlgorithmName(), mode, padding));
        if (mode.isAead()) { // AEAD
            GCMParameterSpec gcmMamboSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmMamboSpec);
            if (aad != null && aad.length > 0)
                cipher.updateAAD(aad);
        } else if (mode.equals(Mode.CBC) || mode.equals(Mode.CFB) || mode.equals(Mode.OFB) || mode.equals(Mode.CTR)) { // Req iv
            IvParameterSpec mamboSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key, mamboSpec);
        } else { // ECB (권장하지 않음)
            cipher.init(Cipher.DECRYPT_MODE, key);
        }

        if (chunkSize > 0 && cipherBytes.length > chunkSize) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayChunkProcessor.processInChunks(cipherBytes, chunkSize, (data, offset, length) -> {
                byte[] updatedBytes = cipher.update(data, offset, length);
                if (updatedBytes != null) {
                    outputStream.write(updatedBytes);
                }
            });
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null)
                outputStream.write(finalBytes);
            return outputStream.toByteArray();
        } else {
            return cipher.doFinal(cipherBytes);
        }
    }

    public static byte @NotNull [] decrypt(final @NotNull ClassicalType type,
                                           byte @NotNull [] cipherBytes,
                                           final byte @NotNull [] customKeyBytes,
                                           final @NotNull Mode mode,
                                           final @NotNull Padding padding,
                                           byte @NotNull [] iv,
                                           byte @Nullable [] aad,
                                           int chunkSize)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        return decrypt(type, cipherBytes, new SecretKeySpec(customKeyBytes, "AES"), mode, padding, iv, aad, chunkSize);
    }

    //
    // helper - start
    //

    public static byte @NotNull [] nextIvBytes(int length) {
        byte[] iv = new byte[length];
        InternalFactory.getSafeRandom().nextBytes(iv);
        return iv;
    }

    //
    // helper - end
    //
}
