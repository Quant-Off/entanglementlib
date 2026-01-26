/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.secure;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.EntLibException;

import java.io.Serial;

public class EntLibSecureIllegalArgumentException extends EntLibSecureException {

    @Serial
    private static final long serialVersionUID = -2452853243888606864L;

    public EntLibSecureIllegalArgumentException() {
        super();
    }

    public EntLibSecureIllegalArgumentException(String message) {
        super(message);
    }

    public EntLibSecureIllegalArgumentException(String message, Throwable cause) {
        super(message, cause);
    }

    public <T> EntLibSecureIllegalArgumentException(Class<T> i18nTargetClass, @NotNull String key) {
        super(i18nTargetClass, key);
    }

    public <T> EntLibSecureIllegalArgumentException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause) {
        super(i18nTargetClass, key, cause);
    }

    public <T> EntLibSecureIllegalArgumentException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause, Object... args) {
        super(i18nTargetClass, key, cause, args);
    }
}
