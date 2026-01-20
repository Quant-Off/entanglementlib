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
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Objects;

/**
 * 고급 암호화 표준(Advanced Encryption Standard, AES) 알고리즘을 사용하기 위한 클래스입니다.
 * 불변 객체(String) 사용에 따른 메모리 잔류 취약점을 해결하기 위해 평문을 받지 않습니다.
 * <p>
 * {@link AutoCloseable}을 구현하여 작업 종료 시 평문, 키를 즉시 영소거 및 파기합니다.
 * try-with-resources 블럭에서의 작업을 권장합니다.
 * <p>
 * 구현에는 다음 사항을 숙지해야 합니다.
 * <ul>
 *     <li>키 생성 알고리즘: {@code AES}</li>
 *     <li>{@code keySize} 전달 여부: {@code true}</li>
 *     <li>암/복호화 시: {@link Mode}, {@link Padding} 필요에 따라 {@link Digest}를 전달해야 하며,
 *                    {@link Mode#getFullName(String, Mode, Padding, Digest) Mode#getFullName(...)}
 *                    메소드로 얻은 문자열 이름을 암호화기에 전달해야 합니다.</li>
 * </ul>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
public final class AES extends AbstractSecureService implements SymmetricCryptoService, AEADService {

    @Getter
    private final ClassicalType type;

    @Getter
    private final int keySize;
    @Getter
    private final Mode mode;
    @Getter
    private final Padding padding;
    @Getter
    private final @Nullable Digest digest;
    private final @NotNull String algorithmFullName;

    /**
     * AES 알고리즘에 사용되는 설정 정보를 담는 레코드 클래스입니다.
     * <p>
     * 암호화된 평문 데이터(암호문), {@code nonce} 바이트 배열, 청크 크기
     * 등의 설정 정보를 포함합니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    public record AESSetting(@Getter ClassicalType type,
                             @Getter Mode mode,
                             @Getter Padding padding,
                             @Getter @Nullable Digest digest,
                             @Getter int chunkSize) {
        @lombok.Builder
        public AESSetting {
        }
    }

    private AES(final @NotNull ClassicalType type,
                @NotNull Mode mode,
                @NotNull Padding padding,
                @Nullable Digest digest) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "AES"));
        this.type = type.getAlgorithmName().contains("AES") ? type : ClassicalType.AES256;
        this.keySize = Integer.parseInt(type.name().replace("AES", ""));
        this.mode = mode == null ? Mode.CBC : mode;
        this.padding = padding == null ? Padding.PKCS5 : padding;
        this.digest = digest;
        this.algorithmFullName = Mode.getFullName(type.getAlgorithmName(), mode, padding, digest);
    }

    public static AES create(final @NotNull ClassicalType type,
                             @NotNull Mode mode,
                             @NotNull Padding padding,
                             @Nullable Digest digest) {
        return new AES(type, mode, padding, digest);
    }

    public static AES create(@NotNull AES.AESSetting aesSetting) {
        return new AES(aesSetting.type(),
                aesSetting.mode(),
                aesSetting.padding(),
                aesSetting.digest());
    }

    @Override
    public CryptoMethod[] getCryptoMethod() {
        return new CryptoMethod[]{CryptoMethod.SYMMETRIC};
    }

    @Override
    public @NotNull EntLibKeyPair generateEntKeyPair(@Nullable EntLibKey.CustomWiper<KeyPair> callback) {
        throw new EntLibAlgorithmSettingException(EntLibCryptoService.class, "not-support-key-type-exc");
    }

    @Override
    public @NotNull EntLibSecretKey generateSecretKey(@Nullable EntLibKey.CustomWiper<SecretKey> callback) throws NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        return register(InternalFactory.Key.secretKeygen(type.getAlgorithmName(), keySize, null), callback);
    }

    public @NotNull String getFullModeName() {
        return Objects.requireNonNull(algorithmFullName);
    }

    @Override
    public byte[] encrypt(@NotNull SecretKey secretKey, byte @NotNull [] plainBytes, byte @NotNull [] iv, byte @Nullable [] aad, int chunkSize)
            throws Exception {
        checkClosed();
        Objects.requireNonNull(iv, "iv");
        Cipher cipher = Cipher.getInstance(Objects.requireNonNull(algorithmFullName));
        if (mode.equals(Mode.AEAD_GCM) || mode.equals(Mode.AEAD_CCM)) { // AEAD
            GCMParameterSpec gcmMamboSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmMamboSpec);
            if (aad != null && aad.length > 0)
                cipher.updateAAD(aad);
        } else if (mode.equals(Mode.CBC) || mode.equals(Mode.CFB) || mode.equals(Mode.OFB) || mode.equals(Mode.CTR)) { // Req iv
            IvParameterSpec mamboSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, mamboSpec);
        } else { // ECB (권장하지 않음)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
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
        return register(ciphertext).clone();
    }

    @Override
    public byte[] decrypt(@NotNull SecretKey secretKey, byte @NotNull [] cipherBytes, byte @NotNull [] iv, byte @Nullable [] aad, int chunkSize)
            throws Exception {
        checkClosed();
        Objects.requireNonNull(iv, "iv");
        Cipher cipher = Cipher.getInstance(Objects.requireNonNull(algorithmFullName));
        if (mode.equals(Mode.AEAD_GCM) || mode.equals(Mode.AEAD_CCM)) { // AEAD
            GCMParameterSpec gcmMamboSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmMamboSpec);
            if (aad != null && aad.length > 0)
                cipher.updateAAD(aad);
        } else if (mode.equals(Mode.CBC) || mode.equals(Mode.CFB) || mode.equals(Mode.OFB) || mode.equals(Mode.CTR)) { // Req iv
            IvParameterSpec mamboSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, mamboSpec);
        } else { // ECB (권장하지 않음)
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
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
            return register(outputStream.toByteArray());
        } else {
            return register(cipher.doFinal(cipherBytes));
        }
    }
}
