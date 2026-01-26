/*
 * Copyright © 2025-2026 Quant.
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
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.critical.EntLibNativeError;
import space.qu4nt.entanglementlib.entlibnative.NativeLinkerManager;
import space.qu4nt.entanglementlib.resource.config.PublicConfiguration;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.EntLibParameterSpec;
import space.qu4nt.entanglementlib.security.PostQuantumParameterSpec;
import space.qu4nt.entanglementlib.security.crypto.EntLibCryptoRegistry;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;
import space.qu4nt.entanglementlib.util.wrapper.Pair;
import tools.jackson.databind.ObjectMapper;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.lang.foreign.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;

/// 환경 변수 할당 및 암호화 연산을 중앙에서 처리하기 위한 내부 클래스입니다.
///
/// `BouncyCastle` 라이브러리 공급자를 `JCA`에 등록하거나 서명, KEM 등의 알고리즘 연산을 간편화할 때 사용됩니다.
/// 필요한 경우 [#_bcNormalProvider] 또는 [#_bcPQCProvider] 상수를 통해 라이브러리 공급자 이름을 사용하거나
/// `JCA`에 공급자를 등록할 수 있습니다.
///
/// @author Q. T. Felix
/// @since 1.0.0
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
    private static String _bcNormalProvider;
    /**
     * BouncyCastle 양자-내성 암호화 공급자 이름입니다.
     */
    private static String _bcPQCProvider;
    /**
     * BouncyCastle JSSE (Java Secure Socket Extension) 공급자 이름입니다.
     */
    private static String _bcJSSEProvider;

    /**
     * 최초 선언 후 변경되지 않는 보안 난수 생성기입니다.
     * <p>
     * 보안 난수를 생성하기 위해 해당 상수만을 사용해야 합니다.
     * <p>
     * {@code BouncyCastle} 라이브러리가 자동으로 최적의 소스를 선택합니다.
     */
    private static final SecureRandom SAFE_RANDOM;

    // TODO: 동적 리소스 할당 로직과 그에 따른 약간의 패턴 변형
    static {
        config = new PublicConfiguration(new ObjectMapper());
        lang = LanguageInstanceBased.create(InternalFactory.class);
        log.debug(lang.argsNonTopKey("loaded-configuration", config));

        SAFE_RANDOM = CryptoServicesRegistrar.getSecureRandom();
        log.debug(lang.msg("init-saferandom"));
    }

    //
    // EntLib-Native - start
    //

    private static final NativeLinkerManager NATIVE;

    static {
        NATIVE = new NativeLinkerManager("entlib_native")
                .addVoidMethodHandle("entanglement_secure_wipe", ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    }

    @NotNull
    public static NativeLinkerManager callNativeLib() {
        if (NATIVE == null)
            throw new EntLibNativeError("네이티브 라이브러리가 등록되지 않았습니다!");
        return NATIVE;
    }

    //
    // EntLib-Native - end
    //

    static void registerInternalEntanglementLib() {
        setupSecurityProviders();
        System.setProperty("jdk.tls.maxHandshakeMessageSize", String.valueOf(config.getTlsMaxHandshakeMessageSize()));
        log.debug("얽힘 라이브러리 레지스트리에 {}개의 알고리즘 등록됨", EntLibCryptoRegistry.registeredCount());
    }

    /**
     * 유틸리티 클래스의 인스턴스화를 방지하기 위한 생성자입니다.
     */
    private InternalFactory() {
        throw new UnsupportedOperationException("InternalFactory");
    }

    /**
     * 등록된 {@link BouncyCastleProvider} 공급자명을 가져오는 메소드입니다.
     *
     * @return {@link BouncyCastleProvider} 공급자명
     */
    public static String getBCNormalProvider() {
        return _bcNormalProvider;
    }

    /**
     * 등록된 {@link BouncyCastlePQCProvider} 공급자명을 가져오는 메소드입니다.
     * <p>
     * 구성에 {@code enabledExperimental} 옵션이 비활성화 되어있으면 해당 공급자를
     * 사용할 수 없습니다.
     *
     * @return {@link BouncyCastlePQCProvider} 공급자명, 구성 비활성화 시 {@code null}
     */
    public static @Nullable String getBCPQCProvider() {
        return _bcPQCProvider;
    }

    /**
     * 등록된 {@link BouncyCastleJsseProvider} 공급자명을 가져오는 메소드입니다.
     *
     * @return {@link BouncyCastleJsseProvider} 공급자명
     */
    public static String getBCJSSEProvider() {
        return _bcJSSEProvider;
    }

    /**
     * 최초 선언 후 변경되지 않는 보안 난수 생성기입니다.
     * <p>
     * 보안 난수를 생성하기 위해 해당 상수만을 사용해야 합니다.
     * <p>
     * {@code BouncyCastle} 라이브러리가 자동으로 최적의 소스(/dev/urandom, Fortuna/PRNG, Auto-seeding 등)를 선택합니다.
     */
    public static SecureRandom getSafeRandom() {
        return SAFE_RANDOM;
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
    static synchronized void setupSecurityProviders() {
        if (isNotBindingSecurityProvider(_bcNormalProvider)) {
            Security.addProvider(new BouncyCastleProvider());
            _bcNormalProvider = BouncyCastleProvider.PROVIDER_NAME;
            log.debug(lang.argsNonTopKey("setting-bc-provider", _bcNormalProvider));
        }

        // NOTE: 실험적 기능이 포함된 공급자는 테스트 시에만 사용
        if (getPublicConfig().isEnabledExperimental()) {
            if (isNotBindingSecurityProvider(_bcPQCProvider)) {
                Security.addProvider(new BouncyCastlePQCProvider());
                _bcPQCProvider = BouncyCastlePQCProvider.PROVIDER_NAME;
                log.debug(lang.argsNonTopKey("setting-bc-provider", _bcPQCProvider));
            }
        }

        if (isNotBindingSecurityProvider(_bcJSSEProvider)) {
            Security.addProvider(new BouncyCastleJsseProvider());
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
    private static void updateSignature(@NotNull Signature signature, byte @NotNull [] plain, int chunkSize) throws SignatureException {
        if (plain.length > 1023 && chunkSize > 0) {
            ByteArrayChunkProcessor.processInChunks(plain, chunkSize, signature::update);
        } else {
            signature.update(plain, 0, plain.length);
        }
    }
}
