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

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.security.builder.signature.SignatureSetting;
import space.qu4nt.entanglementlib.security.EntLibKey;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.util.Nill;

import java.security.*;
import java.util.Arrays;

/**
 * 디지털 서명 알고리즘을 정의하고 서명 생성 및 검증 기능을 제공하는 클래스입니다.
 * <p>
 * 이 클래스는 다양한 서명 알고리즘(특히 PQC 알고리즘 포함)에 대한 상수를 정의하고,
 * {@link EntLibKeyPair}를 사용하여 안전하게 서명을 생성하거나 검증하는 정적 메소드를 제공합니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
@Getter
@ApiStatus.Experimental
public final class Signature extends EntLibAlgorithm<EntLibKeyPair> {

    public static final Signature RSA = new Signature("RSA");
    public static final Signature SHA256withRSA = new Signature("RSA", "SHA256withRSA");
    public static final Signature SHA384withRSA = new Signature("RSA", "SHA384withRSA");
    public static final Signature RSASSA_PSS = new Signature("RSASSA-PSS");

    // FIPS 204
    public static final Signature ML_DSA_44 = new Signature("ML-DSA-44");
    public static final Signature ML_DSA_65 = new Signature("ML-DSA-65");
    public static final Signature ML_DSA_87 = new Signature("ML-DSA-87");
    public static final Signature ML_DSA_44_WITH_SHA_512 = new Signature("ML-DSA-44-WITH-SHA-512");
    public static final Signature ML_DSA_65_WITH_SHA_512 = new Signature("ML-DSA-65-WITH-SHA-512");
    public static final Signature ML_DSA_87_WITH_SHA_512 = new Signature("ML-DSA-87-WITH-SHA-512");

    // FIPS 205
    public static final Signature SLH_DSA_SHA2_128f = new Signature("slh-dsa-sha2-128f");
    public static final Signature SLH_DSA_SHA2_128s = new Signature("slh-dsa-sha2-128s");
    public static final Signature SLH_DSA_SHA2_192f = new Signature("slh-dsa-sha2-192f");
    public static final Signature SLH_DSA_SHA2_192s = new Signature("slh-dsa-sha2-192s");
    public static final Signature SLH_DSA_SHA2_256f = new Signature("slh-dsa-sha2-256f");
    public static final Signature SLH_DSA_SHA2_256s = new Signature("slh-dsa-sha2-256s");
    public static final Signature SLH_DSA_SHAKE_128f = new Signature("slh-dsa-shake-128f");
    public static final Signature SLH_DSA_SHAKE_128s = new Signature("slh-dsa-shake-128s");
    public static final Signature SLH_DSA_SHAKE_192f = new Signature("slh-dsa-shake-192f");
    public static final Signature SLH_DSA_SHAKE_192s = new Signature("slh-dsa-shake-192s");
    public static final Signature SLH_DSA_SHAKE_256f = new Signature("slh-dsa-shake-256f");
    public static final Signature SLH_DSA_SHAKE_256s = new Signature("slh-dsa-shake-256s");
    public static final Signature SLH_DSA_SHA2_128f_WITH_SHA256 = new Signature("slh-dsa-sha2-128f-with-sha256");
    public static final Signature SLH_DSA_SHA2_128s_WITH_SHA256 = new Signature("slh-dsa-sha2-128s-with-sha256");
    public static final Signature SLH_DSA_SHA2_192f_WITH_SHA512 = new Signature("slh-dsa-sha2-192f-with-sha512");
    public static final Signature SLH_DSA_SHA2_192s_WITH_SHA512 = new Signature("slh-dsa-sha2-192s-with-sha512");
    public static final Signature SLH_DSA_SHA2_256f_WITH_SHA512 = new Signature("slh-dsa-sha2-256f-with-sha512");
    public static final Signature SLH_DSA_SHA2_256s_WITH_SHA512 = new Signature("slh-dsa-sha2-256s-with-sha512");
    public static final Signature SLH_DSA_SHAKE_128f_WITH_SHAKE128 = new Signature("slh-dsa-shake-128f-with-shake128");
    public static final Signature SLH_DSA_SHAKE_128s_WITH_SHAKE128 = new Signature("slh-dsa-shake-128s-with-shake128");
    public static final Signature SLH_DSA_SHAKE_192f_WITH_SHAKE256 = new Signature("slh-dsa-shake-192f-with-shake256");
    public static final Signature SLH_DSA_SHAKE_192s_WITH_SHAKE256 = new Signature("slh-dsa-shake-192s-with-shake256");
    public static final Signature SLH_DSA_SHAKE_256f_WITH_SHAKE256 = new Signature("slh-dsa-shake-256f-with-shake256");
    public static final Signature SLH_DSA_SHAKE_256s_WITH_SHAKE256 = new Signature("slh-dsa-shake-256s-with-shake256");

    private String signatureAlgorithm;

    private Signature(String keyGenerateAlgorithm, @Nullable String signatureAlgorithm) {
        super(EntLibKeyPair.class, keyGenerateAlgorithm, 0, false);
        this.signatureAlgorithm = Nill.nullDef(signatureAlgorithm, () -> keyGenerateAlgorithm);
    }

    private Signature(String keyGenerateAlgorithm) {
        this(keyGenerateAlgorithm, null);
    }

    /**
     * 서명 알고리즘을 변경하는 메소드입니다.
     *
     * @param algorithm 사용할 서명 알고리즘
     * @return 인스턴스 반영된 {@link Signature}
     */
    public Signature changeSignatureAlgorithm(@NotNull String algorithm) {
        this.signatureAlgorithm = algorithm;
        return this;
    }

    /**
     * 서명 설정을 위한 빌더를 반환하는 메소드입니다.
     *
     * @return {@link SignatureSetting} 빌더 객체
     */
    public SignatureSetting.SignatureSettingBuilder signatureSetting() {
        return SignatureSetting.builder();
    }

    /**
     * 개인 키를 사용하여 평문 데이터에 서명을 생성하는 메소드입니다.
     * <p>
     * 대용량 데이터의 경우 청크 단위로 처리할 수 있습니다.
     * <p>
     * 전달받은 평문 바이트 배열의 원본을 사용하며, 안전하게 복사된
     * 서명 바이트 배열이 반환됩니다. 작업 완료 후 서명 원본과 키는 소거됩니다.
     *
     * @param signatureAlgType 사용할 서명 알고리즘 객체
     * @param provider         보안 프로바이더 이름 ({@code null}일 경우 기본값 사용)
     * @param plainBytes       서명할 평문 데이터 바이트 배열
     * @param wrappedKey       서명에 사용할 {@link EntLibKeyPair} 키 쌍
     * @param chunkSize        청크 크기 (0인 경우 청크 처리 안 함)
     * @param keyWiperCallback 키 소거 후 호출될 콜백 ({@code null} 허용)
     * @return 생성된 서명 바이트 배열의 복사본
     * @throws SignatureException       서명 생성 중 오류가 발생한 경우
     * @throws NoSuchAlgorithmException 알고리즘을 사용할 수 없는 경우
     * @throws InvalidKeyException      잘못된 개인키가 제공된 경우
     * @throws NoSuchProviderException  지정된 프로바이더를 사용할 수 없는 경우
     */
    public static byte[] sign(@NotNull Signature signatureAlgType,
                              @Nullable String provider,
                              final byte[] plainBytes,
                              EntLibKeyPair wrappedKey,
                              int chunkSize,
                              @Nullable EntLibKey.CustomWiper<KeyPair> keyWiperCallback)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        final KeyPair pair = wrappedKey.keyPair();
        byte[] signature = InternalFactory.Sign.signWithProvider(signatureAlgType.getSignatureAlgorithm(), provider, pair.getPrivate(), plainBytes, chunkSize);
        final byte[] result = Arrays.copyOf(signature, signature.length);

        KeyDestroyHelper.zeroing(signature);
        wrappedKey.wipe(keyWiperCallback);
        return result;
    }

    /**
     * 공개 키를 사용하여 서명을 검증하는 메소드입니다.
     * <p>
     * 대용량 데이터의 경우 청크 단위로 처리할 수 있습니다.
     * 작업 완료 후 서명 데이터와 키는 소거됩니다.
     *
     * @param signatureAlgType 사용할 서명 알고리즘 객체
     * @param provider         보안 프로바이더 이름 ({@code null}일 경우 기본값 사용)
     * @param plainBytes       검증할 평문 데이터 바이트 배열
     * @param signature        검증할 서명 데이터 바이트 배열
     * @param wrappedKey       검증에 사용할 {@link EntLibKeyPair} 키 쌍
     * @param chunkSize        청크 크기 (0인 경우 청크 처리 안 함)
     * @param keyWiperCallback 키 소거 시 호출될 콜백 ({@code null} 허용)
     * @return 서명이 유효하면 {@code true}, 그렇지 않으면 {@code false}
     * @throws NoSuchAlgorithmException 알고리즘을 사용할 수 없는 경우
     * @throws SignatureException       서명 검증 중 오류가 발생한 경우
     * @throws NoSuchProviderException  지정된 프로바이더를 사용할 수 없는 경우
     * @throws InvalidKeyException      잘못된 공개키가 제공된 경우
     */
    public static boolean verify(@NotNull Signature signatureAlgType,
                                 @Nullable String provider,
                                 final byte[] plainBytes,
                                 final byte @NotNull [] signature,
                                 EntLibKeyPair wrappedKey,
                                 int chunkSize,
                                 @Nullable EntLibKey.CustomWiper<KeyPair> keyWiperCallback)
            throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
        final KeyPair pair = wrappedKey.keyPair();
        boolean result = InternalFactory.Sign.verifyWithProvider(signatureAlgType.getSignatureAlgorithm(), provider, pair.getPublic(), plainBytes, signature, chunkSize);

        KeyDestroyHelper.zeroing(signature);
        wrappedKey.wipe(keyWiperCallback);
        return result;
    }

    /**
     * 전자 서명 보안 작업이 수행되는 클래스입니다. 전자 서명은 다음 순서로 동작합니다.
     * 서명 또는 송신자는 앨리스(Alice), 수신자는 밥(Bob)입니다.
     * <p>
     * Alice 측
     * <ol>
     *     <li>Alice: 키 페어 PK, SK 생성</li>
     *     <li>Alice: 평문 해싱 -> 다이제스트 생성</li>
     *     <li>Alice: SK로 다이제스트 서명 -> 서명값 도출</li>
     *     <li>Alice: Bob에게 PK, 평문, 서명값 송신</li>
     * </ol>
     * Bob 측
     * <ol>
     *     <li>Bob: Alice로부터 PK, 평문, 서명값 수신</li>
     *     <li>Bob: 평문 해싱 -> 다이제스트 생성</li>
     *     <li>Bob: Alice의 PK로 평문, 서명값 검증</li>
     *     <li>위 검증 과정에서 Alice의 다이제스트와 비교하는 과정 포함</li>
     * </ol>
     *
     * @author Q. T. Felix
     * @since 1.1.0
     */
    @Deprecated
    static final class Impl {
        public static byte @NotNull [] sign(@NotNull Signature baseAlgorithmObj,
                                            @Nullable String provider,
                                            final byte[] plainBytes,
                                            EntLibKeyPair senderPair,
                                            int chunkSize,
                                            @Nullable EntLibKey.CustomWiper<KeyPair> keyWiperCallback) throws NoSuchAlgorithmException, NoSuchProviderException {
            return new byte[0];
        }
    }
}
