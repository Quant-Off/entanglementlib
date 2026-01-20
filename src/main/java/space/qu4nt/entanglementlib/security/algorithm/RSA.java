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

import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.security.EntLibSignatureException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/**
 * RSA 비대칭키 알고리즘을 사용하여 데이터에 서명하고 검증하는 클래스입니다.
 * 불변 객체(String) 사용에 따른 메모리 잔류 취약점을 해결하기 위해 평문을 받지 않습니다.
 * <p>
 * 보안 강화를 위해 모든 바이트 배열 입출력에 대해 방어적 복사를 수행합니다.
 * <p>
 * {@link AutoCloseable}을 구현하여 작업 종료 시 평문, 서명, 개인키를 즉시 영소거 및 파기합니다.
 * try-with-resources 블럭에서의 작업을 권장합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public final class RSA implements DigitalSignService {

    @Getter
    private final ClassicalType type;
    @Getter
    private final @Nullable Digest digest;

    private byte[] plainBytes;

    private EntLibKeyPair pair;
    private byte[] signature;

    private boolean closed = false;

    /**
     * RSA 서명에 사용되는 설정 정보를 담는 클래스입니다.
     * <p>
     * 서명할 평문 데이터, RSA 타입, 청크 크기 등의
     * 설정 정보를 포함합니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    public static final class Setting {
        private final byte[] plainByteArr;
        @Getter
        private final ClassicalType type;
        @Getter
        private final Digest digest;
        @Getter
        private final int chunkSize;

        @Builder
        public Setting(String plain, byte[] plainByteArr, ClassicalType type, @Nullable Digest digest, int chunkSize) {
            if (plainByteArr != null) {
                this.plainByteArr = plainByteArr.clone(); // 방어적 복사
            } else if (plain != null) {
                this.plainByteArr = plain.getBytes(StandardCharsets.UTF_8);
            } else {
                throw new EntLibAlgorithmSettingException(EntLibCryptoService.class, "plaintext-or-byte-array-exc");
            }
            this.type = (type == null || !type.getMethod().equals(CryptoMethod.ASYMMETRIC)) ?
                    ClassicalType.RSA2048 : type;
            this.digest = digest;
            this.chunkSize = chunkSize;
        }

        public byte[] getPlainByteArr() {
            // 내부 배열 노출 방지를 위한 복사 반환
            return plainByteArr.clone();
        }
    }

    private RSA(final @NotNull ClassicalType type, @Nullable Digest digest, @NotNull String plain) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "RSA"));
        this.type = type;
        this.digest = digest;
        if (this.digest != null)
            type.fixAlgorithmName(digest.getName() + "withRSA");
        this.plainBytes = plain.getBytes(StandardCharsets.UTF_8);
    }

    private RSA(final @NotNull ClassicalType type, @NotNull String plain) {
        this(type, null, plain);
    }

    private RSA(final @NotNull ClassicalType type, @Nullable Digest digest, byte @NotNull [] plainBytes) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "RSA"));
        this.type = type;
        this.digest = digest;
        if (this.digest != null)
            type.fixAlgorithmName(digest.getName() + "withRSA");
        this.plainBytes = Arrays.copyOf(plainBytes, plainBytes.length);
    }

    private RSA(final @NotNull ClassicalType type, byte @NotNull [] plainBytes) {
        this(type, null, plainBytes);
    }

    public static RSA create(final @NotNull ClassicalType type, @Nullable Digest digest, @NotNull String plain) {
        return new RSA(type, digest, plain);
    }

    public static RSA create(final @NotNull ClassicalType type, @NotNull String plain) {
        return create(type, null, plain);
    }

    public static RSA create(final @NotNull ClassicalType type, @Nullable Digest digest, byte @NotNull [] plainBytes) {
        return new RSA(type, digest, plainBytes);
    }

    public static RSA create(final @NotNull ClassicalType type, byte @NotNull [] plainBytes) {
        return create(type, null, plainBytes);
    }

    public static RSA create(@NotNull Setting setting) {
        return new RSA(setting.getType(), setting.getPlainByteArr());
    }

    @Override
    public @NotNull EntLibKeyPair generateEntKeyPair(@Nullable EntLibKey.CustomWiper<KeyPair> callback)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        this.pair = InternalFactory.Key.keyPairGen("RSA", switch (type) {
            case RSA1024 -> 1024;
            case RSA4096 -> 4096;
            default -> 2048;
        }, null);
        return pair;
    }

    @Override
    public byte @NotNull [] getPlainBytes() {
        checkClosed();
        return plainBytes.clone();
    }

    @Override
    public byte[] getSignature() {
        checkClosed();
        return signature != null ? signature.clone() : null;
    }

    @Override
    public byte[] sign(@Nullable String provider, @NotNull PrivateKey sk, int chunkSize)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        byte[] generatedSig;
        if (provider == null)
            generatedSig = InternalFactory.Sign.signWithProvider(type.getAlgorithmName(), null, sk, plainBytes, chunkSize);
        else
            generatedSig = InternalFactory.Sign.signWithProvider(type.getAlgorithmName(), provider, sk, plainBytes, chunkSize);
        this.signature = Arrays.copyOf(generatedSig, generatedSig.length);
        return this.signature.clone();
    }

    @Override
    public boolean verify(@Nullable String provider, @NotNull PublicKey pk, int chunkSize)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        checkClosed();
        if (this.signature == null)
            throw new EntLibSignatureException(DigitalSignService.class, "no-signature-found-exc");
        if (provider == null)
            return InternalFactory.Sign.verifyWithProvider(type.getAlgorithmName(), null, pk, plainBytes, signature, chunkSize);
        return InternalFactory.Sign.verifyWithProvider(type.getAlgorithmName(), provider, pk, plainBytes, signature, chunkSize);
    }

    public void close() throws Exception {
        if (closed) return;

        // 1. 평문 데이터 영소거
        if (plainBytes != null) {
            KeyDestroyHelper.zeroing(plainBytes);
            plainBytes = null;
        }

        // 2. 서명 데이터 영소거 (서명에도 민감 정보가 포함될 수 있음)
        if (signature != null) {
            KeyDestroyHelper.zeroing(signature);
            signature = null;
        }

        // 3. 키 쌍 파기
        if (pair != null) {
            BCRSAPrivateCrtKey sk = (BCRSAPrivateCrtKey) pair.keyPair().getPrivate();
            KeyDestroyHelper.destroy(sk, true);
            pair = null;
        }
        closed = true;
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class).argsNonTopKey("debug-instance-closed", "RSA"));
    }

    private void checkClosed() {
        if (closed) {
            throw new EntLibSecureIllegalStateException(EntLibCryptoService.class, "data-already-destroyed-exc", "RSA");
        }
    }
}
