/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.session;

import space.qu4nt.entanglementlib.exception.EntLibException;
import space.qu4nt.entanglementlib.security.communication.session.Session;

import java.io.Serial;

/// 세션 관련 예외를 나타내는 클래스입니다.
///
/// 세션 생성, 참여자 관리, 상태 전환 등에서 발생할 수 있는
/// 예외 상황을 처리합니다.
///
/// @author Q. T. Felix
/// @see Session
/// @since 1.1.0
public class EntLibSessionException extends EntLibException {

    @Serial
    private static final long serialVersionUID = -4075244968782759826L;

    public EntLibSessionException(String message) {
        super(message);
    }

    public EntLibSessionException(Throwable cause) {
        super(cause);
    }

    public EntLibSessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
