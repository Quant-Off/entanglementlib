package space.qu4nt.entanglementlib.security.provider;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/// FFI 경계를 통해 사용되는 보안 기능별 백엔드 선택을 담는 불변(immutable) 설정입니다.
///
/// 기능(다이제스트·인코딩·AEAD·난수)별로 [CryptoBackend]를 지정하거나, 사용자가 직접 구현한
/// 검증 공급자 인스턴스를 주입할 수 있습니다. 지정하지 않은 기능은 전역 기본 백엔드
/// ([#defaultBackend])를 따릅니다. 기본 백엔드의 초기값은 [CryptoBackend#JDK_VERIFIED]입니다.
///
/// # Examples
/// ```java
/// // 전체를 검증된 JDK 백엔드로 (기본값)
/// CryptoProviderConfig.verifiedDefaults();
///
/// // 전체를 entlib-native로
/// CryptoProviderConfig.nativeDefaults();
///
/// // 기능별 혼합 + 외부 JCA 공급자 + 커스텀 공급자 주입
/// CryptoProviderConfig.builder()
///         .useVerifiedProviders()
///         .aead(CryptoBackend.ENTLIB_NATIVE)
///         .jcaProviderName("BC")
///         .random(myCustomRandomProvider)
///         .build();
/// ```
public final class CryptoProviderConfig {

    private final CryptoBackend defaultBackend;
    private final CryptoBackend digestBackend;
    private final CryptoBackend encodingBackend;
    private final CryptoBackend aeadBackend;
    private final CryptoBackend randomBackend;
    private final DigestProvider customDigest;
    private final EncodingProvider customEncoding;
    private final AeadProvider customAead;
    private final RandomProvider customRandom;
    private final String jcaProviderName;

    private CryptoProviderConfig(final Builder builder) {
        this.defaultBackend = builder.defaultBackend;
        this.digestBackend = builder.digestBackend;
        this.encodingBackend = builder.encodingBackend;
        this.aeadBackend = builder.aeadBackend;
        this.randomBackend = builder.randomBackend;
        this.customDigest = builder.customDigest;
        this.customEncoding = builder.customEncoding;
        this.customAead = builder.customAead;
        this.customRandom = builder.customRandom;
        this.jcaProviderName = builder.jcaProviderName;
    }

    /// 새로운 빌더를 생성합니다. 기본 백엔드는 [CryptoBackend#JDK_VERIFIED]입니다.
    public static Builder builder() {
        return new Builder();
    }

    /// 모든 보안 기능을 검증된 JDK 백엔드로 설정한 구성입니다.
    public static CryptoProviderConfig verifiedDefaults() {
        return builder().useVerifiedProviders().build();
    }

    /// 모든 보안 기능을 `entlib-native` 백엔드로 설정한 구성입니다. (미검증, 시험용)
    public static CryptoProviderConfig nativeDefaults() {
        return builder().useNativeProviders().build();
    }

    CryptoBackend effectiveDigestBackend() {
        return digestBackend != null ? digestBackend : defaultBackend;
    }

    CryptoBackend effectiveEncodingBackend() {
        return encodingBackend != null ? encodingBackend : defaultBackend;
    }

    CryptoBackend effectiveAeadBackend() {
        return aeadBackend != null ? aeadBackend : defaultBackend;
    }

    CryptoBackend effectiveRandomBackend() {
        return randomBackend != null ? randomBackend : defaultBackend;
    }

    @Nullable DigestProvider customDigest() {
        return customDigest;
    }

    @Nullable EncodingProvider customEncoding() {
        return customEncoding;
    }

    @Nullable AeadProvider customAead() {
        return customAead;
    }

    @Nullable RandomProvider customRandom() {
        return customRandom;
    }

    @Nullable String jcaProviderName() {
        return jcaProviderName;
    }

    /// 이 구성이 `entlib-native` 바이너리 로드를 필요로 하는지 여부입니다.
    ///
    /// 어떤 기능이든 커스텀 공급자 없이 [CryptoBackend#ENTLIB_NATIVE]로 해석되면 `true`를 반환합니다.
    /// 모든 기능이 검증 공급자(또는 커스텀)로 해석되면 `false`이며, 이 경우 네이티브 바이너리를
    /// 로드하거나 배포할 필요가 없습니다.
    public boolean requiresNative() {
        return needsNative(customDigest, effectiveDigestBackend())
                || needsNative(customEncoding, effectiveEncodingBackend())
                || needsNative(customAead, effectiveAeadBackend())
                || needsNative(customRandom, effectiveRandomBackend());
    }

    private static boolean needsNative(final Object custom, final CryptoBackend effective) {
        return custom == null && effective == CryptoBackend.ENTLIB_NATIVE;
    }

    /// [CryptoProviderConfig]를 단계적으로 구성하는 빌더입니다.
    public static final class Builder {

        private CryptoBackend defaultBackend = CryptoBackend.JDK_VERIFIED;
        private CryptoBackend digestBackend;
        private CryptoBackend encodingBackend;
        private CryptoBackend aeadBackend;
        private CryptoBackend randomBackend;
        private DigestProvider customDigest;
        private EncodingProvider customEncoding;
        private AeadProvider customAead;
        private RandomProvider customRandom;
        private String jcaProviderName;

        private Builder() {
        }

        /// 기능별로 지정하지 않은 경우 적용할 전역 기본 백엔드를 설정합니다.
        public Builder defaultBackend(final @NotNull CryptoBackend backend) {
            this.defaultBackend = Objects.requireNonNull(backend, "backend");
            return this;
        }

        /// 전역 기본 백엔드를 검증된 JDK로 설정합니다.
        public Builder useVerifiedProviders() {
            this.defaultBackend = CryptoBackend.JDK_VERIFIED;
            return this;
        }

        /// 전역 기본 백엔드를 `entlib-native`로 설정합니다. (미검증, 시험용)
        public Builder useNativeProviders() {
            this.defaultBackend = CryptoBackend.ENTLIB_NATIVE;
            return this;
        }

        /// 다이제스트 기능의 백엔드를 지정합니다.
        public Builder digest(final @NotNull CryptoBackend backend) {
            this.digestBackend = Objects.requireNonNull(backend, "backend");
            this.customDigest = null;
            return this;
        }

        /// 다이제스트 기능에 사용자 정의 검증 공급자를 주입합니다.
        public Builder digest(final @NotNull DigestProvider provider) {
            this.customDigest = Objects.requireNonNull(provider, "provider");
            return this;
        }

        /// 인코딩 기능의 백엔드를 지정합니다.
        public Builder encoding(final @NotNull CryptoBackend backend) {
            this.encodingBackend = Objects.requireNonNull(backend, "backend");
            this.customEncoding = null;
            return this;
        }

        /// 인코딩 기능에 사용자 정의 검증 공급자를 주입합니다.
        public Builder encoding(final @NotNull EncodingProvider provider) {
            this.customEncoding = Objects.requireNonNull(provider, "provider");
            return this;
        }

        /// AEAD 기능의 백엔드를 지정합니다.
        public Builder aead(final @NotNull CryptoBackend backend) {
            this.aeadBackend = Objects.requireNonNull(backend, "backend");
            this.customAead = null;
            return this;
        }

        /// AEAD 기능에 사용자 정의 검증 공급자를 주입합니다.
        public Builder aead(final @NotNull AeadProvider provider) {
            this.customAead = Objects.requireNonNull(provider, "provider");
            return this;
        }

        /// 난수 기능의 백엔드를 지정합니다.
        public Builder random(final @NotNull CryptoBackend backend) {
            this.randomBackend = Objects.requireNonNull(backend, "backend");
            this.customRandom = null;
            return this;
        }

        /// 난수 기능에 사용자 정의 검증 공급자를 주입합니다.
        public Builder random(final @NotNull RandomProvider provider) {
            this.customRandom = Objects.requireNonNull(provider, "provider");
            return this;
        }

        /// 검증된 JDK 백엔드가 사용할 외부 JCA 공급자명을 지정합니다 (예: `BC`).
        /// `null`이면 JDK 기본 공급자를 사용합니다.
        public Builder jcaProviderName(final @Nullable String jcaProviderName) {
            this.jcaProviderName = jcaProviderName;
            return this;
        }

        public CryptoProviderConfig build() {
            return new CryptoProviderConfig(this);
        }
    }
}
