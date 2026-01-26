/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.tls;

/// TLS 서버의 생명주기 상태를 나타내는 열거형입니다.
///
/// @author Q. T. Felix
/// @see Server
/// @since 1.1.0
public enum ServerState {

    /// 서버가 생성되었지만 아직 시작되지 않았습니다.
    CREATED,

    /// 서버가 시작 중입니다. 리소스를 초기화하고 있습니다.
    STARTING,

    /// 서버가 실행 중이며 클라이언트 연결을 수락할 준비가 되었습니다.
    RUNNING,

    /// 서버가 종료 중입니다. 연결을 정리하고 있습니다.
    STOPPING,

    /// 서버가 정상적으로 종료되었습니다.
    STOPPED,

    /// 서버가 오류로 인해 실패했습니다.
    FAILED
}
