/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.server;

import space.qu4nt.entanglementlib.exception.EntLibException;
import space.qu4nt.entanglementlib.security.communication.session.Session;

import java.io.Serial;

/// @author Q. T. Felix
/// @see Session
/// @since 1.1.0
public class EntLibServerIllegalStateException extends EntLibException {

    @Serial
    private static final long serialVersionUID = 709411898221020869L;

    public EntLibServerIllegalStateException(String message) {
        super(message);
    }

    public EntLibServerIllegalStateException(Throwable cause) {
        super(cause);
    }

    public EntLibServerIllegalStateException(String message, Throwable cause) {
        super(message, cause);
    }
}
