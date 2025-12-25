/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.resource.config;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.exception.config.EntLibConfigException;
import space.qu4nt.entanglementlib.resource.ResourceCaller;
import space.qu4nt.entanglementlib.resource.language.SupportedLanguage;
import space.qu4nt.entanglementlib.security.EntLibParameterSpec;
import space.qu4nt.entanglementlib.security.algorithm.MLDSAType;
import space.qu4nt.entanglementlib.security.algorithm.SLHDSAType;
import space.qu4nt.entanglementlib.util.StringUtil;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Objects;

/**
 * {@code public} 디렉토리에 정의된 구성 파일 {@code configuration.json}을
 * 호출하는 클래스입니다.
 * <p>
 * 이 클래스는 {@link space.qu4nt.entanglementlib.InternalFactory}에서
 * 정적 선언되고 할당값을 변경하지 않습니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
@Getter
@Setter
public final class PublicConfiguration {

    private PublicConfigTree publicConfigTree;

    private SupportedLanguage language;
    private boolean isEnabledExperimental;
    private String tlsProtocol;
    private boolean enabledPQC;
    private EntLibParameterSpec tlsRootCACertAlgorithm;
    private EntLibParameterSpec tlsServerCertAlgorithm;
    private int tlsMaxHandshakeMessageSize;

    /**
     * Jackson 라이브러리를 사용하여 얽힘 라이브러리의 구성 파일을 역직렬화한 후
     * 전역 변수에 할당하는 생성자입니다.
     *
     * @param mapper 역직렬화에 사용될 매퍼
     */
    public PublicConfiguration(final @NotNull ObjectMapper mapper) {
        try {
            this.publicConfigTree = ResourceCaller.jacksonDeserializeInPublic(
                    mapper,
                    "configuration.json",
                    PublicConfigTree.class
            );
        } catch (IOException e) {
            throw new EntLibConfigException(PublicConfiguration.class, "deserialize-exc", e);
        }

        validation();
    }

    private void validation() {
        Objects.requireNonNull(publicConfigTree, "public config");

        // 언어 기본: ko_KR
        try {
            this.language = SupportedLanguage.valueOf(this.publicConfigTree.getLanguage());
        } catch (IllegalArgumentException e) {
            this.language = SupportedLanguage.ko_KR;
        }

        // 데모 로직 활성화 여부
        this.isEnabledExperimental = this.publicConfigTree.getSecure().isEnabledExperimental();

        // tls protocol 기본: TLSv1.3
        @Nullable String tlsProtocol = this.publicConfigTree.getSecure().getTls().getProtocol();
        if (isNullOrEmpty(tlsProtocol)) {
            this.tlsProtocol = "TLSv1.3";
        } else if (tlsProtocol.trim().equalsIgnoreCase("TLSv1.1")) {
            log.warn("The TLSv1.1 protocol is not available in the EntanglementLib. Therefore, I set the protocol to the default value of 'TLSv1.3'.");
            this.tlsProtocol = "TLSv1.3";
        } else {
            this.tlsProtocol = tlsProtocol.trim();
        }

        // 루트 및 서버 인증서 생성 알고리즘 검증
        this.enabledPQC = this.publicConfigTree.getSecure().getTls().getCert().isEnabledPQC();
        // PQC = true인 경우 사용 가능한 알고리즘은 mldsa, slhdsa밖에 없음. 이 중에 찾으면 됌
        @Nullable String rootAlg = this.publicConfigTree.getSecure().getTls().getCert().getRoot();
        if (isNullOrEmpty(rootAlg)) {
            this.tlsRootCACertAlgorithm = SLHDSAType.SLH_DSA_SHA2_256s;
        } else if (enabledPQC && (rootAlg.contains("slh-dsa"))) {
            SLHDSAType.fromName(StringUtil.toLowerCase(rootAlg))
                    .ifPresent(slhdsaType -> this.tlsRootCACertAlgorithm = slhdsaType);
        } else if (enabledPQC && (rootAlg.contains("ml-dsa"))) {
            MLDSAType.fromName(StringUtil.toLowerCase(rootAlg))
                    .ifPresent(mldsaType -> this.tlsRootCACertAlgorithm = mldsaType);
        } else {
            // TODO: 고전 알고리즘 로직
        }

        @Nullable String servAlg = this.publicConfigTree.getSecure().getTls().getCert().getServer();
        if (isNullOrEmpty(servAlg)) {
            this.tlsServerCertAlgorithm = MLDSAType.ML_DSA_87;
        } else if (enabledPQC && (servAlg.contains("slh-dsa"))) {
            SLHDSAType.fromName(StringUtil.toLowerCase(servAlg))
                    .ifPresent(slhdsaType -> this.tlsServerCertAlgorithm = slhdsaType);
        } else if (enabledPQC && (servAlg.contains("ml-dsa"))) {
            MLDSAType.fromName(StringUtil.toLowerCase(servAlg))
                    .ifPresent(mldsaType -> this.tlsServerCertAlgorithm = mldsaType);
        } else {
            // TODO: 고전 알고리즘 로직
        }

        // 핸드셰이크 메시지 사이즈 기본: 131072
        int size = this.publicConfigTree.getSecure().getTls().getMaxHandshakeMessageSize();
        if (size < 1 || size > Integer.MAX_VALUE) {
            this.tlsMaxHandshakeMessageSize = 131072;
        } else {
            this.tlsMaxHandshakeMessageSize = size;
        }
    }

    @Override
    public String toString() {
        return """
                PublicConfiguration: {
                  "language": "%s",
                  "secure": {
                    "enabledExperimental": %b,
                    "tls": {
                      "protocol": "%s",
                      "cert": {
                        "enabledPQC": %b,
                        "root": "%s",
                        "server": "%s"
                      },
                      "maxHandshakeMessageSize": %d
                    }
                  }
                }""".formatted(language.name(),
                isEnabledExperimental,
                tlsProtocol,
                enabledPQC,
                tlsRootCACertAlgorithm.getAlgorithmName(),
                tlsServerCertAlgorithm.getAlgorithmName(),
                tlsMaxHandshakeMessageSize);
    }

    private boolean isNullOrEmpty(final String value) {
        return value == null || value.isEmpty();
    }
}
