/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.session;

/// 세션의 생명주기 상태를 나타내는 열거형입니다.
///
/// @author Q. T. Felix
/// @see Session
/// @since 1.1.0
public enum SessionState {

    /// 세션이 생성되었지만 아직 활성화되지 않았습니다.
    CREATED,

    /// 세션이 활성 상태입니다. 참여자가 참여하고 통신할 수 있습니다.
    ACTIVE,

    /// 세션이 일시 중단되었습니다. 새 참여자 참여가 차단됩니다.
    SUSPENDED,

    /// 세션이 종료 중입니다. 정리 작업이 진행 중입니다.
    CLOSING,

    /// 세션이 정상적으로 종료되었습니다.
    CLOSED,

    /// 세션이 오류로 인해 강제 종료되었습니다.
    TERMINATED
}
