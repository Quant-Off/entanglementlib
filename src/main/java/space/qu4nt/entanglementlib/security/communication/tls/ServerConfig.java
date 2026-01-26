/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.tls;

import lombok.Builder;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.communication.session.SessionConfig;

/// TLS 서버 설정을 담는 불변 클래스입니다.
///
/// ## 사용 예시
/// ```java
/// ServerConfig config = ServerConfig.builder()
///     .port(8443)
///     .bindAddress("0.0.0.0")
///     .backlog(128)
///     .sessionConfig(SessionConfig.highSecurity())
///     .build();
/// ```
///
/// @author Q. T. Felix
/// @see Server
/// @see SessionConfig
/// @since 1.1.0
@Getter
@Builder
public class ServerConfig {

    /// 기본 포트
    public static final int DEFAULT_PORT = 8443;

    /// 기본 바인드 주소
    public static final String DEFAULT_BIND_ADDRESS = "0.0.0.0";

    /// 기본 백로그 크기
    public static final int DEFAULT_BACKLOG = 128;

    /// 서버 포트
    @Builder.Default
    private final int port = DEFAULT_PORT;

    /// 바인드 주소
    @Builder.Default
    private final String bindAddress = DEFAULT_BIND_ADDRESS;

    /// 연결 대기열 크기 (백로그)
    @Builder.Default
    private final int backlog = DEFAULT_BACKLOG;

    /// 세션 설정
    @Builder.Default
    private final SessionConfig sessionConfig = SessionConfig.defaults();

    /// 단일 세션 모드 여부 (모든 클라이언트가 하나의 세션 공유)
    @Builder.Default
    private final boolean singleSessionMode = false;

    /// 서버 이름 (디버깅/로깅용)
    private final String serverName;

    /// 기본 설정으로 ServerConfig를 생성합니다.
    ///
    /// @return 기본 설정의 ServerConfig
    @NotNull
    public static ServerConfig defaults() {
        return ServerConfig.builder().build();
    }

    /// 개발용 설정으로 ServerConfig를 생성합니다.
    ///
    /// @param port 서버 포트
    /// @return 개발용 설정의 ServerConfig
    @NotNull
    public static ServerConfig development(int port) {
        return ServerConfig.builder()
                .port(port)
                .sessionConfig(SessionConfig.lightweight())
                .singleSessionMode(true)
                .build();
    }

    /// 프로덕션용 고보안 설정으로 ServerConfig를 생성합니다.
    ///
    /// @param port 서버 포트
    /// @return 프로덕션용 고보안 설정의 ServerConfig
    @NotNull
    public static ServerConfig production(int port) {
        return ServerConfig.builder()
                .port(port)
                .backlog(256)
                .sessionConfig(SessionConfig.highSecurity())
                .build();
    }
}
