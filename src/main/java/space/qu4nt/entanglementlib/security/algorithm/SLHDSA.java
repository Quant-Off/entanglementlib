/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.algorithm;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPrivateKey;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibAlgorithmSettingException;
import space.qu4nt.entanglementlib.exception.security.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.exception.security.EntLibSignatureException;
import space.qu4nt.entanglementlib.resource.language.Language;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntKeyPair;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/**
 * SLH-DSA 양자-내성 서명 알고리즘을 사용하여 데이터에 서명하고 검증하는 클래스입니다.
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
public final class SLHDSA implements DigitalSignService {

    @Getter
    private final SLHDSAType type;
    private byte[] plainBytes;

    private EntKeyPair pair;
    private byte[] signature;

    private boolean closed = false;

    /**
     * ML-DSA 서명에 사용되는 설정 정보를 담는 클래스입니다.
     * <p>
     * 서명할 평문 데이터, ML-DSA 타입, 청크 크기 등의
     * 설정 정보를 포함합니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    public static class SLHDSASetting {
        private final byte[] plainByteArr;
        @Getter
        private final SLHDSAType type;
        @Getter
        private final int chunkSize;

        @lombok.Builder
        public SLHDSASetting(String plain, byte[] plainByteArr, SLHDSAType type, int chunkSize) {
            if (plainByteArr != null) {
                this.plainByteArr = plainByteArr.clone(); // 방어적 복사
            } else if (plain != null) {
                this.plainByteArr = plain.getBytes(StandardCharsets.UTF_8);
            } else {
                throw new EntLibAlgorithmSettingException(EntLibCryptoService.class, "plaintext-or-byte-array-exc");
            }
            this.type = type == null ? SLHDSAType.SLH_DSA_SHA2_256s : type;
            this.chunkSize = chunkSize;
        }

        public byte[] getPlainByteArr() {
            // 내부 배열 노출 방지를 위한 복사 반환
            return plainByteArr.clone();
        }
    }

    // 생성자: String 입력 시 즉시 바이트 변환 후 String 참조 유지 안 함
    private SLHDSA(final @NotNull SLHDSAType type, @NotNull String plain) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "SLH-DSA"));
        this.type = type;
        this.plainBytes = plain.getBytes(StandardCharsets.UTF_8);
    }

    // 생성자: byte[] 입력 시 방어적 복사 수행
    private SLHDSA(final @NotNull SLHDSAType type, byte @NotNull [] plainBytes) {
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class)
                .argsNonTopKey("debug-created-instance", "SLH-DSA"));
        this.type = type;
        this.plainBytes = Arrays.copyOf(plainBytes, plainBytes.length);
    }

    public static SLHDSA create(final @NotNull SLHDSAType type, @NotNull String plain) {
        return new SLHDSA(type, plain);
    }

    public static SLHDSA create(final @NotNull SLHDSAType type, byte @NotNull [] plainBytes) {
        return new SLHDSA(type, plainBytes);
    }

    public static SLHDSA create(@NotNull SLHDSASetting slhdsaSetting) {
        // Setting에서 가져올 때도 이미 복사된 배열을 가져오거나 생성자에서 복사됨
        return new SLHDSA(slhdsaSetting.getType(), slhdsaSetting.getPlainByteArr());
    }

    @Override
    public @NotNull EntKeyPair generateEntKeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        this.pair = new EntKeyPair(InternalFactory.Key.keygenWithPQC(type));
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

    /**
     * 개인 키를 사용하여 평문 데이터에 SLH-DSA 서명을 생성하는 메소드입니다.
     * <p>
     * 대용량 데이터의 경우 청크 단위로 처리할 수 있습니다.
     *
     * @param sk        서명에 사용할 개인키
     * @param chunkSize 청크 크기 (0인 경우 청크 처리 안 함)
     * @return 생성된 서명 바이트 배열
     * @throws InvalidKeyException      잘못된 개인키가 제공된 경우
     * @throws SignatureException       서명 생성 중 오류가 발생한 경우
     * @throws NoSuchAlgorithmException SLH-DSA 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException  지정된 프로바이더를 사용할 수 없는 경우
     */
    @Override
    public byte[] sign(final @NotNull PrivateKey sk, int chunkSize)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        checkClosed();
        byte[] generatedSig = InternalFactory.Sign.sign(type, sk, plainBytes, chunkSize);
        this.signature = Arrays.copyOf(generatedSig, generatedSig.length);
        return this.signature.clone();
    }

    /**
     * 공개 키를 사용하여 평문 데이터와 SLH-DSA 서명을 검증하는 메소드입니다.
     * <p>
     * 대용량 데이터의 경우 청크 단위로 처리할 수 있습니다.
     *
     * @param pk        검증에 사용할 공개키
     * @param chunkSize 청크 크기 (0인 경우 청크 처리 안 함)
     * @return 서명이 유효한 경우 true, 그렇지 않으면 false
     * @throws NoSuchAlgorithmException SLH-DSA 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException  지정된 프로바이더를 사용할 수 없는 경우
     * @throws InvalidKeyException      잘못된 공개키가 제공된 경우
     * @throws SignatureException       서명 검증 중 오류가 발생한 경우
     */
    @Override
    public boolean verify(final @NotNull PublicKey pk, int chunkSize)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        checkClosed();
        if (this.signature == null)
            throw new EntLibSignatureException(DigitalSignService.class, "no-signature-found-exc");
        return InternalFactory.Sign.verify(type, pk, plainBytes, signature, chunkSize);
    }

    @Override
    public void close() {
        if (closed) return;

        if (plainBytes != null) {
            KeyDestroyHelper.zeroing(plainBytes);
            log.debug(LanguageInstanceBased.create(DigitalSignService.class)
                    .argsNonTopKey("debug-plain-bytes-zeroing-result", Hex.toHexString(plainBytes)));
            plainBytes = null;
        }

        if (signature != null) {
            KeyDestroyHelper.zeroing(signature);
            log.debug(LanguageInstanceBased.create(DigitalSignService.class)
                    .argsNonTopKey("debug-signature-bytes-zeroing-result", Hex.toHexString(signature)));
            signature = null;
        }

        if (pair != null) {
            BCSLHDSAPrivateKey sk = (BCSLHDSAPrivateKey) pair.keyPair().getPrivate();
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
        log.debug(LanguageInstanceBased.create(EntLibCryptoService.class).argsNonTopKey("debug-instance-closed", "SLH-DSA"));
    }

    private void checkClosed() {
        if (closed) {
            throw new EntLibSecureIllegalStateException(EntLibCryptoService.class, "data-already-destroyed-exc", "SLH-DSA");
        }
    }
}