/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.security.EntLibSignatureException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntKeyPair;
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

    private byte[] plainBytes;

    private EntKeyPair pair;
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
        private final int chunkSize;

        @lombok.Builder
        public Setting(String plain, byte[] plainByteArr, ClassicalType type, int chunkSize) {
            if (plainByteArr != null) {
                this.plainByteArr = plainByteArr.clone(); // 방어적 복사
            } else if (plain != null) {
                this.plainByteArr = plain.getBytes(StandardCharsets.UTF_8);
            } else {
                throw new EntLibAlgorithmSettingException(EntLibCryptoService.class, "plaintext-or-byte-array-exc");
            }
            this.type = (type == null || !type.getMethod().equals(CryptoMethod.ASYMMETRIC)) ?
                    ClassicalType.RSA2048 : type;
            this.chunkSize = chunkSize;
        }

        public byte[] getPlainByteArr() {
            // 내부 배열 노출 방지를 위한 복사 반환
            return plainByteArr.clone();
        }
    }

    private RSA(final @NotNull ClassicalType type, @NotNull String plain) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "RSA"));
        this.type = type;
        this.plainBytes = plain.getBytes(StandardCharsets.UTF_8);
    }

    private RSA(final @NotNull ClassicalType type, byte @NotNull [] plainBytes) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "RSA"));
        this.type = type;
        this.plainBytes = Arrays.copyOf(plainBytes, plainBytes.length);
    }

    public static RSA create(final @NotNull ClassicalType type, @NotNull String plain) {
        return new RSA(type, plain);
    }

    public static RSA create(final @NotNull ClassicalType type, byte @NotNull [] plainBytes) {
        return new RSA(type, plainBytes);
    }

    public static RSA create(@NotNull Setting setting) {
        return new RSA(setting.getType(), setting.getPlainByteArr());
    }

    @Override
    public @NotNull EntKeyPair generateEntKeyPair()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        this.pair = new EntKeyPair(InternalFactory.Key.keygenWithKeySize("RSA", switch (type) {
            case RSA1024 -> 1024;
            case RSA4096 -> 4096;
            default -> 2048;
        }));
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
    public byte[] sign(@NotNull PrivateKey sk, int chunkSize)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        byte[] generatedSig = InternalFactory.Sign.sign(type, sk, plainBytes, chunkSize);
        this.signature = Arrays.copyOf(generatedSig, generatedSig.length);
        return this.signature.clone();
    }

    @Override
    public boolean verify(@NotNull PublicKey pk, int chunkSize)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        checkClosed();
        if (this.signature == null)
            throw new EntLibSignatureException(DigitalSignService.class, "no-signature-found-exc");
        return InternalFactory.Sign.verify(type, pk, plainBytes, signature, chunkSize);
    }

    @Override
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
