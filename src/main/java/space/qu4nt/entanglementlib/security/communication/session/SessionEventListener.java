/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.session;

/// 세션 이벤트를 수신하는 리스너 인터페이스입니다.
///
/// 세션의 생명주기와 참여자 변경 이벤트를 처리할 수 있습니다.
/// 모든 메소드는 기본 구현(no-op)을 제공하므로 필요한 이벤트만
/// 선택적으로 오버라이드할 수 있습니다.
///
/// ## 사용 예시
/// ```java
/// session.addEventListener(new SessionEventListener() {
///     @Override
///     public void onParticipantJoined(Session session, Participant participant) {
///         System.out.println("새 참여자: " + participant.getId());
///     }
/// });
/// ```
///
/// @author Q. T. Felix
/// @see Session
/// @since 1.1.0
public interface SessionEventListener {

    /// 참여자가 세션에 참여했을 때 호출됩니다.
    ///
    /// @param session     세션
    /// @param participant 참여한 참여자
    default void onParticipantJoined(Session session, Participant participant) {
    }

    /// 참여자가 세션에서 나갔을 때 호출됩니다.
    ///
    /// @param session     세션
    /// @param participant 나간 참여자
    default void onParticipantLeft(Session session, Participant participant) {
    }

    /// 세션 상태가 변경되었을 때 호출됩니다.
    ///
    /// @param session  세션
    /// @param oldState 이전 상태
    /// @param newState 새 상태
    default void onSessionStateChanged(Session session, SessionState oldState, SessionState newState) {
    }

    /// 세션이 종료 중일 때 호출됩니다.
    /// 정리 작업이 시작되기 전에 호출됩니다.
    ///
    /// @param session 세션
    default void onSessionClosing(Session session) {
    }

    /// 세션이 정상 종료되었을 때 호출됩니다.
    ///
    /// @param session 세션
    default void onSessionClosed(Session session) {
    }

    /// 세션이 강제 종료되었을 때 호출됩니다.
    ///
    /// @param session 세션
    default void onSessionTerminated(Session session) {
    }

    /// 세션 보안 컨텍스트가 변경되었을 때 호출됩니다.
    ///
    /// @param session 세션
    default void onSecurityContextChanged(Session session) {
    }

    /// 세션에서 오류가 발생했을 때 호출됩니다.
    ///
    /// @param session   세션
    /// @param throwable 발생한 오류
    default void onSessionError(Session session, Throwable throwable) {
    }
}
