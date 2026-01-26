/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.tls;

import space.qu4nt.entanglementlib.security.communication.session.Participant;

import java.nio.ByteBuffer;

/// TLS 서버 이벤트를 수신하는 리스너 인터페이스입니다.
///
/// 서버의 생명주기, 클라이언트 연결, 핸드셰이크, 데이터 수신 등의
/// 이벤트를 처리할 수 있습니다. 모든 메서드는 기본 구현(no-op)을
/// 제공하므로 필요한 이벤트만 선택적으로 오버라이드할 수 있습니다.
///
/// ## 사용 예시
/// ```java
/// server.addEventListener(new ServerEventListener() {
///     @Override
///     public void onClientConnected(Server server, Participant participant) {
///         System.out.println("클라이언트 연결: " + participant.getId());
///     }
///
///     @Override
///     public void onHandshakeCompleted(Server server, Participant participant) {
///         System.out.println("핸드셰이크 완료: " + participant.getId());
///     }
/// });
/// ```
///
/// @author Q. T. Felix
/// @see Server
/// @since 1.1.0
public interface ServerEventListener {

    /// 서버가 시작되었을 때 호출됩니다.
    ///
    /// @param server 서버 인스턴스
    default void onServerStarted(Server server) {
    }

    /// 서버가 종료되었을 때 호출됩니다.
    ///
    /// @param server 서버 인스턴스
    default void onServerStopped(Server server) {
    }

    /// 새 클라이언트가 연결되었을 때 호출됩니다.
    /// 핸드셰이크 시작 전에 호출됩니다.
    ///
    /// @param server      서버 인스턴스
    /// @param participant 연결된 참여자
    default void onClientConnected(Server server, Participant participant) {
    }

    /// 클라이언트 연결이 종료되었을 때 호출됩니다.
    ///
    /// @param server      서버 인스턴스
    /// @param participant 연결이 종료된 참여자
    default void onClientDisconnected(Server server, Participant participant) {
    }

    /// 클라이언트와의 핸드셰이크가 완료되었을 때 호출됩니다.
    /// 이 시점부터 보안 통신이 가능합니다.
    ///
    /// @param server      서버 인스턴스
    /// @param participant 핸드셰이크가 완료된 참여자
    default void onHandshakeCompleted(Server server, Participant participant) {
    }

    /// 클라이언트로부터 데이터를 수신했을 때 호출됩니다.
    /// 핸드셰이크 완료 후 애플리케이션 데이터만 전달됩니다.
    ///
    /// @param server      서버 인스턴스
    /// @param participant 데이터를 보낸 참여자
    /// @param data        수신된 데이터 (복호화된 상태)
    default void onDataReceived(Server server, Participant participant, ByteBuffer data) {
    }

    /// 서버에서 오류가 발생했을 때 호출됩니다.
    ///
    /// @param server    서버 인스턴스
    /// @param throwable 발생한 오류
    default void onServerError(Server server, Throwable throwable) {
    }
}
