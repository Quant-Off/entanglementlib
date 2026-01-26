/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.session;

import lombok.Builder;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.crypto.KEMType;
import space.qu4nt.entanglementlib.security.crypto.SignatureType;

import java.time.Duration;

/// 세션 설정을 담는 불변 클래스입니다.
///
/// 빌더 패턴을 사용하여 세션의 다양한 설정을 구성할 수 있습니다.
///
/// ## 사용 예시
/// ```java
/// SessionConfig config = SessionConfig.builder()
///     .maxParticipants(10)
///     .sessionTimeout(Duration.ofHours(1))
///     .idleTimeout(Duration.ofMinutes(15))
///     .kemType(KEMType.ML_KEM_768)
///     .signatureType(SignatureType.ML_DSA_65)
///     .build();
/// ```
///
/// @author Q. T. Felix
/// @see Session
/// @since 1.1.0
@Getter
@Builder
public class SessionConfig {

    /// 기본 최대 참여자 수 (0 = 무제한)
    public static final int DEFAULT_MAX_PARTICIPANTS = 0;

    /// 기본 세션 타임아웃 (24시간)
    public static final Duration DEFAULT_SESSION_TIMEOUT = Duration.ofHours(24);

    /// 기본 유휴 타임아웃 (30분)
    public static final Duration DEFAULT_IDLE_TIMEOUT = Duration.ofMinutes(30);

    /// 기본 인바운드 버퍼 크기 (64KB)
    public static final int DEFAULT_BUFFER_SIZE = 64 * 1024;

    /// 최대 참여자 수 (0 = 무제한)
    @Builder.Default
    private final int maxParticipants = DEFAULT_MAX_PARTICIPANTS;

    /// 세션 전체 타임아웃 (세션 생성 후 최대 유지 시간)
    @Builder.Default
    private final Duration sessionTimeout = DEFAULT_SESSION_TIMEOUT;

    /// 유휴 타임아웃 (마지막 활동 후 세션 종료까지 시간)
    @Builder.Default
    private final Duration idleTimeout = DEFAULT_IDLE_TIMEOUT;

    /// 참여자별 인바운드 버퍼 크기
    @Builder.Default
    private final int bufferSize = DEFAULT_BUFFER_SIZE;

    /// 세션에서 사용할 기본 KEM 알고리즘
    @Builder.Default
    private final KEMType defaultKemType = KEMType.ML_KEM_768;

    /// 세션에서 사용할 기본 서명 알고리즘
    @Builder.Default
    private final SignatureType defaultSignatureType = SignatureType.ML_DSA_65;

    /// 클래식 ECDH(X25519) 사용 여부 (하이브리드 모드용)
    @Builder.Default
    private final boolean useClassicEcdh = true;

    /// 자동 재연결 허용 여부
    @Builder.Default
    private final boolean allowReconnection = true;

    /// 재연결 허용 시간 (연결 끊김 후 재연결 가능 시간)
    @Builder.Default
    private final Duration reconnectionWindow = Duration.ofMinutes(5);

    /// 핸드셰이크 타임아웃
    @Builder.Default
    private final Duration handshakeTimeout = Duration.ofSeconds(30);

    /// 세션 이름 (선택적, 디버깅/로깅용)
    private final String sessionName;

    /// 세션 메타데이터 (사용자 정의 데이터)
    private final Object metadata;

    /// 기본 설정으로 SessionConfig를 생성합니다.
    ///
    /// @return 기본 설정의 SessionConfig
    @NotNull
    public static SessionConfig defaults() {
        return SessionConfig.builder().build();
    }

    /// 고보안 설정으로 SessionConfig를 생성합니다.
    /// [KEMType#X25519MLKEM768]과 [SignatureType#ML_DSA_87]을 사용하며,
    /// 짧은 타임아웃을 적용합니다.
    ///
    /// @return 고보안 설정의 SessionConfig
    @NotNull
    public static SessionConfig highSecurity() {
        return SessionConfig.builder()
                .defaultKemType(KEMType.X25519MLKEM768)
                .defaultSignatureType(SignatureType.ML_DSA_87)
                .sessionTimeout(Duration.ofHours(4))
                .idleTimeout(Duration.ofMinutes(10))
                .handshakeTimeout(Duration.ofSeconds(15))
                .allowReconnection(false)
                .build();
    }

    /// 경량 설정으로 SessionConfig를 생성합니다.
    /// ML-KEM-512와 ML-DSA-44를 사용하며, 긴 타임아웃을 적용합니다.
    ///
    /// @return 경량 설정의 SessionConfig
    @NotNull
    public static SessionConfig lightweight() {
        return SessionConfig.builder()
                .defaultKemType(KEMType.ML_KEM_512)
                .defaultSignatureType(SignatureType.ML_DSA_44)
                .sessionTimeout(Duration.ofHours(48))
                .idleTimeout(Duration.ofHours(2))
                .handshakeTimeout(Duration.ofSeconds(60))
                .build();
    }

    /// 세션 타임아웃을 밀리초 단위로 반환합니다.
    ///
    /// @return 세션 타임아웃 (밀리초)
    public long getSessionTimeoutMillis() {
        return sessionTimeout.toMillis();
    }

    /// 유휴 타임아웃을 밀리초 단위로 반환합니다.
    ///
    /// @return 유휴 타임아웃 (밀리초)
    public long getIdleTimeoutMillis() {
        return idleTimeout.toMillis();
    }

    /// 핸드셰이크 타임아웃을 밀리초 단위로 반환합니다.
    ///
    /// @return 핸드셰이크 타임아웃 (밀리초)
    public long getHandshakeTimeoutMillis() {
        return handshakeTimeout.toMillis();
    }

    /// 재연결 허용 시간을 밀리초 단위로 반환합니다.
    ///
    /// @return 재연결 허용 시간 (밀리초)
    public long getReconnectionWindowMillis() {
        return reconnectionWindow.toMillis();
    }
}
