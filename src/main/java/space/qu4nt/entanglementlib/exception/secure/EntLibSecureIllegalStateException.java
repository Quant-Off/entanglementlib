/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.secure;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.EntLibException;

import java.io.Serial;

public class EntLibSecureIllegalStateException extends EntLibException {

    @Serial
    private static final long serialVersionUID = -5903209133861840394L;

    public EntLibSecureIllegalStateException() {
        super();
    }

    public EntLibSecureIllegalStateException(String message) {
        super(message);
    }

    public <T> EntLibSecureIllegalStateException(Class<T> i18nTargetClass, @NotNull String key) {
        super(i18nTargetClass, key);
    }

    public <T> EntLibSecureIllegalStateException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause) {
        super(i18nTargetClass, key, cause);
    }

    public <T> EntLibSecureIllegalStateException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause, Object... args) {
        super(i18nTargetClass, key, cause, args);
    }
}
