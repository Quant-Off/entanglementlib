/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.critical;

import java.io.Serial;

public class EntLibNativeError extends EntLibError {

    @Serial
    private static final long serialVersionUID = -1665435182140213888L;

    public EntLibNativeError(String message) {
        super(message);
    }

    public EntLibNativeError(String message, Throwable cause) {
        super(message, cause);
    }
}
