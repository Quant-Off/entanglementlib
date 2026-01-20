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
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.wrapper.Hex;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/**
 * ML-KEM 양자-내성 키 캡슐화 메커니즘을 사용하여 데이터를 캡슐화하는 클래스입니다.
 * <p>
 * 보안 강화를 위해 내부적으로 평문 데이터를 String으로 유지하지 않으며, 모든 바이트 배열
 * 입출력에 대해 방어적 복사를 수행합니다.
 * <p>
 * {@link AutoCloseable}을 구현하여 작업 종료 시 평문, 서명, 개인키를 즉시 영소거 및 파기합니다.
 * try-with-resources 블럭에서의 작업을 권장합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public final class MLKEM implements KeyEncapsulateService {

    @Getter
    private final MLKEMType type;
    private byte[] plainBytes;

    private EntLibKeyPair pair;
    private Pair<byte[], SecretKey> capsule;

    private boolean closed = false;

    /**
     * ML-KEM 캡슐화에 사용되는 설정 정보를 담는 클래스입니다.
     * <p>
     * 암호화할 평문 데이터, ML-KEM 타입 설정 정보를 포함합니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    public static class MLKEMSetting {
        private final byte[] plainBytes;
        @Getter
        private final MLKEMType type;

        @lombok.Builder
        public MLKEMSetting(String plain, byte[] plainBytes, MLKEMType type) {
            if (plainBytes != null) {
                this.plainBytes = plainBytes.clone(); // 방어적 복사
            } else if (plain != null) {
                this.plainBytes = plain.getBytes(StandardCharsets.UTF_8);
            } else {
                throw new EntLibAlgorithmSettingException(MLKEM.class, "plaintext-or-byte-array-exc");
            }
            this.type = type == null ? MLKEMType.ML_KEM_768 : type;
        }

        public byte[] getPlainBytes() {
            return plainBytes.clone();
        }
    }

    private MLKEM(final @NotNull MLKEMType type, @NotNull String plain) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "ML-KEM"));
        this.type = type;
        this.plainBytes = plain.getBytes(StandardCharsets.UTF_8);
    }

    private MLKEM(final @NotNull MLKEMType type, byte @NotNull [] plainBytes) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "ML-KEM"));
        this.type = type;
        this.plainBytes = Arrays.copyOf(plainBytes, plainBytes.length);
    }

    public static MLKEM create(final @NotNull MLKEMType type, @NotNull String plain) {
        return new MLKEM(type, plain);
    }

    public static MLKEM create(final @NotNull MLKEMType type, byte @NotNull [] plainBytes) {
        return new MLKEM(type, plainBytes);
    }

    public static MLKEM create(@NotNull MLKEMSetting mlkemSetting) {
        return new MLKEM(mlkemSetting.getType(), mlkemSetting.getPlainBytes());
    }

    @Override
    public @NotNull EntLibKeyPair generateEntKeyPair(@Nullable EntLibKey.CustomWiper<KeyPair> callback)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        this.pair = new EntLibKeyPair(InternalFactory.Key.keygenWithPQC(type));
        return pair;
    }

    public byte @NotNull [] getPlainBytes() {
        checkClosed();
        return plainBytes.clone();
    }

    @Override
    public Pair<byte[], SecretKey> encapsulate(@NotNull PublicKey pk) throws GeneralSecurityException {
        checkClosed();
        this.capsule = InternalFactory.KEM.encapsulate(type, pk);
        return new Pair<>(capsule.getFirst().clone(), capsule.getSecond());
    }

    @Override
    public byte[] decapsulate(@NotNull SecretKey secretKey, @NotNull PrivateKey sk, byte @NotNull [] ciphertext) throws GeneralSecurityException {
        checkClosed();
        return InternalFactory.KEM.decapsulate(type, secretKey, sk, ciphertext);
    }

    public void close() throws Exception {
        if (closed) return;

        if (plainBytes != null) {
            KeyDestroyHelper.zeroing(plainBytes);
            log.debug(LanguageInstanceBased.create(KeyEncapsulateService.class)
                    .argsNonTopKey("debug-plain-bytes-zeroing-result", Hex.toHexString(plainBytes)));
            plainBytes = null;
        }

        if (capsule != null) {
            KeyDestroyHelper.zeroing(capsule.getFirst());
            // NOTE: Java 9 부터 강력한 캡슐화 지원으로
            // 모듈화된 경우 리플렉션으로도 접근 불가능하여
            // 형식적으로만 제거함. getEncoded()를 통해 호출된 바이트 배열은
            // 당연하게도 복제본임.
            KeyDestroyHelper.zeroing(capsule.getSecond().getEncoded());

            log.debug(LanguageInstanceBased.create(KeyEncapsulateService.class)
                    .argsNonTopKey("debug-capsule-bytes-zeroing-result", Hex.toHexString(capsule.getFirst()), Hex.toHexString(capsule.getSecond().getEncoded())));
            capsule = null;
        }

        if (pair != null) {
            BCMLKEMPrivateKey sk = (BCMLKEMPrivateKey) pair.keyPair().getPrivate();
            try {
                Field params = sk.getClass().getDeclaredField("params");
                params.setAccessible(true);
                KeyDestroyHelper.destroy(params.get(sk));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            pair = null;
        }
        closed = true;
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class).argsNonTopKey("debug-instance-closed", "ML-KEM"));
    }

    private void checkClosed() {
        if (closed) {
            throw new EntLibSecureIllegalStateException(EntLibCryptoService.class, "data-already-destroyed-exc", "ML-KEM");
        }
    }
}
