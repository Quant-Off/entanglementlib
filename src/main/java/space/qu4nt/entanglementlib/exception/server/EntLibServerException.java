/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.server;

import space.qu4nt.entanglementlib.exception.EntLibException;
import space.qu4nt.entanglementlib.security.communication.session.Session;

import java.io.Serial;

/// 서버 관련 예외를 나타내는 클래스입니다.
///
/// @author Q. T. Felix
/// @see Session
/// @since 1.1.0
public class EntLibServerException extends EntLibException {

    @Serial
    private static final long serialVersionUID = 9158866932313942233L;

    public EntLibServerException(String message) {
        super(message);
    }

    public EntLibServerException(Throwable cause) {
        super(cause);
    }

    public EntLibServerException(String message, Throwable cause) {
        super(message, cause);
    }
}
