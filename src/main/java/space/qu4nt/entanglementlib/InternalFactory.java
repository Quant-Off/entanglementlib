/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.resource.config.PublicConfiguration;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntLibParameterSpec;
import space.qu4nt.entanglementlib.security.PostQuantumParameterSpec;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;
import space.qu4nt.entanglementlib.util.wrapper.Pair;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Objects;

/**
 * 암호화 연산을 중앙에서 처리하기 위한 내부 클래스입니다.
 * <p>
 * {@code BouncyCastle} 라이브러리 공급자를 {@code JCA}에 등록하거나 서명, KEM 등의 알고리즘 연산을 간편화할 때 사용됩니다.
 * 필요한 경우 {@link #_bcNormalProvider} 또는 {@link #_bcPQCProvider} 상수를 통해 라이브러리 공급자 이름을 사용하거나
 * {@code JCA}에 공급자를 등록할 수 있습니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@ApiStatus.Internal
@Slf4j
public final class InternalFactory extends EntanglementLibEnvs {

    /**
     * 얽힘 라이브러리의 공개 구성입니다. 라이브러리 로드 시 가장 먼저 초기화되어야 합니다.
     */
    private static final PublicConfiguration config;
    /**
     * {@link InternalFactory} 클래스에 대한 다국어 지원 인스턴스입니다.
     */
    private static final LanguageInstanceBased<InternalFactory> lang;

    /**
     * BouncyCastle 일반 및 NIST 표준화된 암호화 공급자 이름입니다.
     */
    public static String _bcNormalProvider;
    /**
     * BouncyCastle 양자-내성 암호화 공급자 이름입니다.
     */
    public static String _bcPQCProvider;
    /**
     * BouncyCastle JSSE (Java Secure Socket Extension) 공급자 이름입니다.
     */
    public static String _bcJSSEProvider;

    /**
     * 최초 선언 후 변경되지 않는 보안 난수 생성기입니다.
     * <p>
     * 보안 난수를 생성하기 위해 해당 상수만을 사용해야 합니다.
     * <p>
     * {@code BouncyCastle} 라이브러리가 자동으로 최적의 소스(/dev/urandom, Fortuna/PRNG, Auto-seeding 등)를 선택합니다.
     */
    public static final SecureRandom SAFE_RANDOM;

    static {
        config = new PublicConfiguration(new ObjectMapper());
        lang = LanguageInstanceBased.create(InternalFactory.class);
        log.info(lang.argsNonTopKey("loaded-configuration", config));

        setupSecurityProviders();
        System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(config.getTlsMaxHandshakeMessageSize()));

        SAFE_RANDOM = CryptoServicesRegistrar.getSecureRandom();
        log.debug(lang.msg("init-saferandom"));
    }

    /**
     * 유틸리티 클래스의 인스턴스화를 방지하기 위한 생성자입니다.
     */
    private InternalFactory() {
        throw new UnsupportedOperationException("InternalFactory");
    }

    /**
     * 라이브러리의 공개 구성을 가져오는 메소드입니다.
     *
     * @return {@link PublicConfiguration} 인스턴스
     */
    public static PublicConfiguration getPublicConfig() {
        return Objects.requireNonNull(config, "public config");
    }

    /**
     * 지정된 이름의 보안 공급자가 등록되어 있지 않은지 확인하는 메소드입니다.
     *
     * @param provider 확인할 공급자 이름
     * @return 등록되어 있지 않으면 {@code true}, 그렇지 않으면 {@code false}
     */
    static boolean isNotBindingSecurityProvider(String provider) {
        return getSpecificProvider(provider) == null;
    }

    /**
     * 지정된 이름의 보안 공급자를 가져오는 메소드입니다.
     *
     * @param provider 가져올 공급자 이름
     * @return {@link Provider} 인스턴스, 없으면 {@code null}
     */
    static Provider getSpecificProvider(String provider) {
        return Security.getProvider(provider);
    }

    /**
     * BouncyCastle 보안 공급자를 JCA에 등록하는 메소드입니다.
     * <p>
     * 일반, PQC, JSSE 공급자를 순서대로 등록하며, 실험적 기능 사용 여부에 따라 PQC 공급자 등록이 결정됩니다.
     * 멀티 스레드 환경에서의 안전한 등록을 위해 동기화 처리되었습니다.
     */
    public static synchronized void setupSecurityProviders() {
        if (isNotBindingSecurityProvider(_bcNormalProvider)) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            _bcNormalProvider = BouncyCastleProvider.PROVIDER_NAME;
            log.debug(lang.argsNonTopKey("setting-bc-provider", _bcNormalProvider));
        }

        // NOTE: 실험적 기능이 포함된 공급자는 테스트 시에만 사용
        if (getPublicConfig().isEnabledExperimental()) {
            if (isNotBindingSecurityProvider(_bcPQCProvider)) {
                Security.insertProviderAt(new BouncyCastlePQCProvider(), 1);
                _bcPQCProvider = BouncyCastlePQCProvider.PROVIDER_NAME;
                log.debug(lang.argsNonTopKey("setting-bc-provider", _bcPQCProvider));
            }
        }

        if (isNotBindingSecurityProvider(_bcJSSEProvider)) {
            Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
            _bcJSSEProvider = BouncyCastleJsseProvider.PROVIDER_NAME;
            log.debug(lang.argsNonTopKey("setting-bc-provider", _bcJSSEProvider));
        }
    }

    /**
     * {@link Signature} 객체에 평문 데이터를 업데이트하는 공통 메소드입니다.
     * <p>
     * 대용량 데이터의 경우 청크 단위로 처리하며, 작은 데이터는 일반 업데이트를 수행합니다.
     * 이 메소드는 서명 생성 및 검증 과정에서 공통으로 사용됩니다.
     *
     * @param signature 업데이트할 Signature 객체
     * @param plain     업데이트할 평문 데이터
     * @param chunkSize 청크 크기 (0 이하인 경우 일반 처리)
     * @throws SignatureException 서명 업데이트 중 예외가 발생한 경우
     */
    public static void updateSignature(@NotNull Signature signature, byte @NotNull [] plain, int chunkSize) throws SignatureException {
        if (plain.length > 1023 && chunkSize > 0) {
            ByteArrayChunkProcessor.processInChunks(plain, chunkSize, signature::update);
        } else {
            signature.update(plain, 0, plain.length);
        }
    }

    /**
     * 키 생성 관련 유틸리티 클래스입니다.
     */
    public static final class Key {
        /**
         * 유틸리티 클래스의 인스턴스화를 방지하기 위한 생성자입니다.
         */
        private Key() {
            throw new UnsupportedOperationException("Singleton");
        }

        /**
         * 양자내성암호(PQC) 알고리즘으로 키 쌍을 생성하는 메소드입니다.
         *
         * @param type PQC 파라미터 스펙
         * @return 생성된 {@link KeyPair}
         * @throws NoSuchAlgorithmException 지원하지 않는 알고리즘일 경우
         * @throws NoSuchProviderException  지원하지 않는 공급자일 경우
         */
        public static KeyPair keygenWithPQC(@NotNull PostQuantumParameterSpec type)
                throws NoSuchAlgorithmException, NoSuchProviderException {
            Objects.requireNonNull(type);
            log.debug("키 페어 생성 - 양자 내성 알고리즘: {}", type.getAlgorithmName());

            final KeyPairGenerator generator = KeyPairGenerator.getInstance(type.getAlgorithmName(), _bcNormalProvider);
            return generator.generateKeyPair();
        }

        /**
         * 고전 암호화 알고리즘으로 키 쌍을 생성하는 메소드입니다.
         *
         * @param baseAlg 기본 알고리즘 이름 (예: "RSA")
         * @param keySize 키 크기 (비트 단위)
         * @return 생성된 {@link KeyPair}
         * @throws NoSuchAlgorithmException 지원하지 않는 알고리즘일 경우
         */
        public static KeyPair keygenWithKeySize(@NotNull String baseAlg, int keySize)
                throws NoSuchAlgorithmException {
            Objects.requireNonNull(baseAlg);
            if (keySize < 0)
                throw new IllegalArgumentException("keySize < 0");
            log.debug("키 페어 생성 - 고전 알고리즘: {}", baseAlg);

            KeyPairGenerator generator = KeyPairGenerator.getInstance(baseAlg);
            generator.initialize(keySize, SAFE_RANDOM);
            return generator.generateKeyPair();
        }

        public static SecretKey secretKeygen(@NotNull String baseAlg, int keySize)
                throws NoSuchAlgorithmException {
            Objects.requireNonNull(baseAlg);
            if (keySize < 0)
                throw new IllegalArgumentException("keySize < 0");
            log.debug("대칭키 생성 - 고전 알고리즘: {}", baseAlg);

            KeyGenerator generator = KeyGenerator.getInstance(baseAlg);
            generator.init(keySize, SAFE_RANDOM);
            return generator.generateKey();
        }
    }

    /**
     * 디지털 서명 생성 및 검증 관련 유틸리티 클래스입니다.
     */
    public static final class Sign {
        /**
         * 유틸리티 클래스의 인스턴스화를 방지하기 위한 생성자입니다.
         */
        private Sign() {
            throw new UnsupportedOperationException("Singleton");
        }

        /**
         * 주어진 데이터에 대해 디지털 서명을 생성하는 메소드입니다.
         *
         * @param type       서명 파라미터 스펙
         * @param privateKey 서명에 사용할 개인키
         * @param plain      서명할 평문 데이터
         * @param chunkSize  데이터 처리 시 청크 크기
         * @return 생성된 서명 값
         * @throws InvalidKeyException      유효하지 않은 키일 경우
         * @throws SignatureException       서명 생성 중 오류 발생 시
         * @throws NoSuchAlgorithmException 지원하지 않는 알고리즘일 경우
         * @throws NoSuchProviderException  지원하지 않는 공급자일 경우
         */
        public static byte[] sign(@NotNull EntLibParameterSpec type,
                                  @NotNull PrivateKey privateKey,
                                  byte @NotNull [] plain,
                                  int chunkSize)
                throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
            Objects.requireNonNull(type);
            Objects.requireNonNull(privateKey);
            Objects.requireNonNull(plain);
            log.debug("서명 수행 - 알고리즘: {}", type.getAlgorithmName());

            Signature signature = Signature.getInstance(type.getAlgorithmName(), _bcNormalProvider);
            signature.initSign(privateKey, SAFE_RANDOM);
            updateSignature(signature, plain, chunkSize);
            return signature.sign();
        }

        /**
         * 주어진 데이터와 서명을 검증하는 메소드입니다.
         *
         * @param type      서명 파라미터 스펙
         * @param publicKey 검증에 사용할 공개키
         * @param plain     원본 평문 데이터
         * @param signature 검증할 서명 값
         * @param chunkSize 데이터 처리 시 청크 크기
         * @return 서명이 유효하면 {@code true}, 그렇지 않으면 {@code false}
         * @throws NoSuchAlgorithmException 지원하지 않는 알고리즘일 경우
         * @throws NoSuchProviderException  지원하지 않는 공급자일 경우
         * @throws InvalidKeyException      유효하지 않은 키일 경우
         * @throws SignatureException       서명 검증 중 오류 발생 시
         */
        public static boolean verify(@NotNull EntLibParameterSpec type,
                                     @NotNull PublicKey publicKey,
                                     byte @NotNull [] plain,
                                     byte @NotNull [] signature,
                                     int chunkSize)
                throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
            Objects.requireNonNull(type);
            Objects.requireNonNull(publicKey);
            Objects.requireNonNull(plain);
            Objects.requireNonNull(signature);
            log.debug("서명 검증 수행 - 알고리즘: {}", type.getAlgorithmName());

            Signature verifier = Signature.getInstance(type.getAlgorithmName(), _bcNormalProvider);
            verifier.initVerify(publicKey);
            updateSignature(verifier, plain, chunkSize);
            return verifier.verify(signature);
        }
    }

    /**
     * 키 캡슐화 메커니즘(KEM) 관련 유틸리티 클래스입니다.
     */
    public static final class KEM {
        /**
         * 유틸리티 클래스의 인스턴스화를 방지하기 위한 생성자입니다.
         */
        private KEM() {
            throw new UnsupportedOperationException("Singleton");
        }

        /**
         * 공개키를 사용하여 공유 비밀키와 암호화된 캡슐을 생성하는 메소드입니다.
         *
         * @param publicKey 수신자의 공개키
         * @return 암호화된 캡슐(ciphertext)과 공유 비밀키(shared secret)를 담은 {@link Pair}
         * @throws GeneralSecurityException 캡슐화 과정에서 오류 발생 시
         */
        public static Pair<byte[], SecretKey> encapsulate(@NotNull EntLibParameterSpec type, final @NotNull PublicKey publicKey) throws GeneralSecurityException {
            Objects.requireNonNull(publicKey);
            log.debug("KEM 캡슐화 수행 - 알고리즘: {}, 타임스탬프: {}", type.getAlgorithmName(), System.currentTimeMillis());

            javax.crypto.KEM kemSender = javax.crypto.KEM.getInstance(type.getAlgorithmName(), _bcNormalProvider);
            javax.crypto.KEM.Encapsulator encapsulator = kemSender.newEncapsulator(publicKey);
            javax.crypto.KEM.Encapsulated encapsulated = encapsulator.encapsulate();

            byte[] cipherText = encapsulated.encapsulation();
            SecretKey sharedSecretKeySender = encapsulated.key();
            return new Pair<>(cipherText.clone(), sharedSecretKeySender);
        }

        /**
         * 개인키와 암호화된 캡슐을 사용하여 공유 비밀키를 복호화하는 메소드입니다.
         *
         * @param secretKey  디캡슐화에 사용할 비밀키 (알고리즘 지정용)
         * @param privateKey 수신자의 개인키
         * @param ciphertext 암호화된 캡슐
         * @return 복호화된 공유 비밀키
         * @throws GeneralSecurityException 디캡슐화 과정에서 오류 발생 시
         */
        public static byte[] decapsulate(@NotNull EntLibParameterSpec type, final @NotNull SecretKey secretKey, final @NotNull PrivateKey privateKey, byte @NotNull [] ciphertext) throws GeneralSecurityException {
            Objects.requireNonNull(secretKey);
            Objects.requireNonNull(privateKey);
            Objects.requireNonNull(ciphertext);
            log.debug("KEM 디캡슐화 수행 - 알고리즘: {}, 타임스탬프: {}", type.getAlgorithmName(), System.currentTimeMillis());

            javax.crypto.KEM kemReceiver = javax.crypto.KEM.getInstance(type.getAlgorithmName(), _bcNormalProvider);
            javax.crypto.KEM.Decapsulator decapsulator = kemReceiver.newDecapsulator(privateKey);
            SecretKey sharedSecretKeyReceiver = decapsulator.decapsulate(ciphertext);
            return sharedSecretKeyReceiver.getEncoded();
        }
    }

}
