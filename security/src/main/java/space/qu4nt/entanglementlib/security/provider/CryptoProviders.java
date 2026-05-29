package space.qu4nt.entanglementlib.security.provider;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import space.qu4nt.entanglementlib.security.provider.entlibnative.EntLibNativeAeadProvider;
import space.qu4nt.entanglementlib.security.provider.entlibnative.EntLibNativeDigestProvider;
import space.qu4nt.entanglementlib.security.provider.entlibnative.EntLibNativeEncodingProvider;
import space.qu4nt.entanglementlib.security.provider.entlibnative.EntLibNativeRandomProvider;
import space.qu4nt.entanglementlib.security.provider.jdk.JdkAeadProvider;
import space.qu4nt.entanglementlib.security.provider.jdk.JdkDigestProvider;
import space.qu4nt.entanglementlib.security.provider.jdk.JdkEncodingProvider;
import space.qu4nt.entanglementlib.security.provider.jdk.JdkRandomProvider;

import java.util.Objects;

/// 현재 활성화된 보안 공급자들을 보관하는 전역 레지스트리입니다. 공개 파사드([Hash], [Base64] 등)는
/// 이 레지스트리를 통해 설정된 백엔드로 위임합니다.
///
/// [#install]을 호출하기 전 기본값은 모든 기능을 검증된 JDK 백엔드로 사용합니다(안전 우선). 따라서
/// 명시적 초기화 없이도 검증된 연산이 즉시 가능합니다.
public final class CryptoProviders {

    private static final Logger log = LoggerFactory.getLogger(CryptoProviders.class);

    private static volatile DigestProvider digest;
    private static volatile EncodingProvider encoding;
    private static volatile AeadProvider aead;
    private static volatile RandomProvider random;

    static {
        install(CryptoProviderConfig.verifiedDefaults());
    }

    private CryptoProviders() {
        throw new AssertionError("cannot access");
    }

    /// 전달된 구성에 따라 공급자들을 해석하여 전역 레지스트리에 설치합니다.
    /// 사용자 정의 공급자가 주입된 기능은 해당 인스턴스를, 그 외에는 선택된 백엔드의 내장 구현을 사용합니다.
    public static synchronized void install(final @NotNull CryptoProviderConfig config) {
        Objects.requireNonNull(config, "config");
        digest = resolveDigest(config);
        encoding = resolveEncoding(config);
        aead = resolveAead(config);
        random = resolveRandom(config);
        log.info("보안 공급자 설치 완료 -> digest='{}', encoding='{}', aead='{}', random='{}'",
                digest.backendName(), encoding.backendName(), aead.backendName(), random.backendName());
    }

    public static DigestProvider digest() {
        return digest;
    }

    public static EncodingProvider encoding() {
        return encoding;
    }

    public static AeadProvider aead() {
        return aead;
    }

    public static RandomProvider random() {
        return random;
    }

    private static DigestProvider resolveDigest(final CryptoProviderConfig config) {
        if (config.customDigest() != null) return config.customDigest();
        return switch (config.effectiveDigestBackend()) {
            case JDK_VERIFIED -> new JdkDigestProvider(config.jcaProviderName());
            case ENTLIB_NATIVE -> new EntLibNativeDigestProvider();
        };
    }

    private static EncodingProvider resolveEncoding(final CryptoProviderConfig config) {
        if (config.customEncoding() != null) return config.customEncoding();
        return switch (config.effectiveEncodingBackend()) {
            case JDK_VERIFIED -> new JdkEncodingProvider();
            case ENTLIB_NATIVE -> new EntLibNativeEncodingProvider();
        };
    }

    private static AeadProvider resolveAead(final CryptoProviderConfig config) {
        if (config.customAead() != null) return config.customAead();
        return switch (config.effectiveAeadBackend()) {
            case JDK_VERIFIED -> new JdkAeadProvider(config.jcaProviderName());
            case ENTLIB_NATIVE -> new EntLibNativeAeadProvider();
        };
    }

    private static RandomProvider resolveRandom(final CryptoProviderConfig config) {
        if (config.customRandom() != null) return config.customRandom();
        return switch (config.effectiveRandomBackend()) {
            case JDK_VERIFIED -> new JdkRandomProvider();
            case ENTLIB_NATIVE -> new EntLibNativeRandomProvider();
        };
    }
}
