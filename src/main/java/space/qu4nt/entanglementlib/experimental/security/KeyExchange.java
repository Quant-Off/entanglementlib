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
import lombok.Setter;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.experimental.security.builder.exchange.KeyExchangeSetting;
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.EntLibSecretKey;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.util.Arrays;
import java.util.Objects;

/**
 * 키 교환(Key Agreement) 알고리즘을 정의하고 수행하는 클래스입니다. 일관성을 위해 Key Exchange로 작명했습니다.
 * <p>
 * 주로 ECDH(X25519 등)와 같은 고전적 키 교환 방식을 지원하며,
 * {@link EntLibKeyPair}와 상대방의 {@link PublicKey}를 사용하여 공유 비밀(shared secret)을 생성합니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Getter
@Setter
@ApiStatus.Experimental
public class KeyExchange extends EntLibAlgorithm<EntLibKeyPair> {

    public static final KeyExchange X448 = new KeyExchange("X448");
    public static final KeyExchange X448WITHSHA512KDF = new KeyExchange("X448", "X448WITHSHA512KDF");
    public static final KeyExchange X448WITHSHA256CKDF = new KeyExchange("X448", "X448WITHSHA256CKDF");
    public static final KeyExchange X448withSHA512HKDF = new KeyExchange("X448", "X448withSHA512HKDF");
    public static final KeyExchange X448UWITHSHA512KDF = new KeyExchange("X448", "X448UWITHSHA512KDF");
    public static final KeyExchange X448WITHSHA384CKDF = new KeyExchange("X448", "X448WITHSHA384CKDF");
    public static final KeyExchange X448WITHSHA512CKDF = new KeyExchange("X448", "X448WITHSHA512CKDF");

    public static final KeyExchange X25519 = new KeyExchange("X25519");
    public static final KeyExchange X25519_WITH_SHA_256_KDF = new KeyExchange("X25519", "X25519WITHSHA256KDF");
    public static final KeyExchange X25519_WITH_SHA_512_CKDF = new KeyExchange("X25519", "X25519WITHSHA512CKDF");
    public static final KeyExchange X25519_WITH_SHA_384_CKDF = new KeyExchange("X25519", "X25519WITHSHA384CKDF");
    public static final KeyExchange X25519_WITH_SHA_256_CKDF = new KeyExchange("X25519", "X25519WITHSHA256CKDF");
    public static final KeyExchange X25519_with_SHA_256_HKDF = new KeyExchange("X25519", "X25519withSHA256HKDF");

    public static final KeyExchange ECDH = new KeyExchange("ECDH");
    public static final KeyExchange ECDHC = new KeyExchange("ECDH", "ECDHC");
    public static final KeyExchange ECDHWITHSHA1KDF = new KeyExchange("ECDH", "ECDHWITHSHA1KDF");
    public static final KeyExchange ECDHWITHSHA384KDF = new KeyExchange("ECDH", "ECDHWITHSHA384KDF");
    public static final KeyExchange ECDHWITHSHA512KDF = new KeyExchange("ECDH", "ECDHWITHSHA512KDF");
    public static final KeyExchange ECDHWITHSHA256KDF = new KeyExchange("ECDH", "ECDHWITHSHA256KDF");
    public static final KeyExchange ECDHWITHSHA224KDF = new KeyExchange("ECDH", "ECDHWITHSHA224KDF");

    public static final KeyExchange XDH = new KeyExchange("XDH");

    public static final KeyExchange ECMQV = new KeyExchange("ECMQV");

    private String keyAgreementAlgorithm;

    private KeyExchange(String keyGenerateAlgorithm, @Nullable String keyAgreementAlgorithm) {
        super(EntLibKeyPair.class, keyGenerateAlgorithm, 0, false);
        this.keyAgreementAlgorithm = keyAgreementAlgorithm == null ? keyGenerateAlgorithm : keyAgreementAlgorithm;
    }

    private KeyExchange(String keyAgreementAlgorithm) {
        this(keyAgreementAlgorithm, null);
    }

    public KeyExchangeSetting.KeyExchangeSettingBuilder keyExchangeSetting() {
        return KeyExchangeSetting.builder();
    }

    /**
     * 자신의 키 쌍과 상대방의 공개 키를 사용하여 공유 비밀을 생성하는 인스턴스 메소드입니다.
     *
     * @param provider       보안 프로바이더 이름 ({@code null}일 경우 기본값 사용)
     * @param wrappedKeyYour 자신의 키 쌍 (개인키 포함)
     * @param publicKeyOther 상대방의 공개 키
     * @return 생성된 공유 비밀({@link EntLibSecretKey})
     * @throws NoSuchAlgorithmException 지정된 알고리즘을 찾을 수 없는 경우
     * @throws NoSuchProviderException  지정된 프로바이더를 찾을 수 없는 경우
     * @throws InvalidKeyException      유효하지 않은 키가 제공된 경우
     */
    public EntLibSecretKey generateSecret(@Nullable String provider,
                                          EntLibKeyPair wrappedKeyYour,
                                          PublicKey publicKeyOther)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        return genAgreementSecret(this, provider, wrappedKeyYour, publicKeyOther);
    }

    /**
     * 공유 비밀을 생성하는 정적 헬퍼 메소드입니다.
     *
     * @param keyExchange    사용할 키 교환 알고리즘 객체
     * @param provider       보안 프로바이더 이름
     * @param wrappedKeyYour 자신의 키 쌍
     * @param publicKeyOther 상대방의 공개 키
     * @return 생성된 공유 비밀
     */
    public static EntLibSecretKey genAgreementSecret(final @NotNull KeyExchange keyExchange,
                                                     @Nullable String provider,
                                                     EntLibKeyPair wrappedKeyYour,
                                                     PublicKey publicKeyOther)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        // Validation
        final KeyPair pair = Objects.requireNonNull(wrappedKeyYour).keyPair();

        KeyAgreement agreement;
        if (provider == null)
            agreement = KeyAgreement.getInstance(keyExchange.getKeyGenerateAlgorithm());
        else
            agreement = KeyAgreement.getInstance(keyExchange.getKeyGenerateAlgorithm(), provider);

        agreement.init(pair.getPrivate());
        agreement.doPhase(publicKeyOther, true);

        // KeyAgreement.generateSecret()은 새로운 바이트 배열 반환
        byte[] secret = agreement.generateSecret();
        return new EntLibSecretKey(secret);
    }

    /**
     * 두 공유 비밀의 바이트 배열이 일치하는지 확인하는 메소드입니다.
     * TODO: 상수 시간 비교 필요, 임시: Arrays.equals
     *
     * @return 두 공유 비밀 바이트 배열이 일치하는 경우 true, 그렇지 않으면 false
     */
    public static boolean agreementKeyEqual(byte[] secretBytesYour, byte[] secretBytesOther) {
        // TODO: 타이밍 공격 방지를 위해 MessageDigest.isEqual 등 상수 시간 비교 로직 도입 고려
        return Arrays.equals(secretBytesYour, secretBytesOther);
    }
}