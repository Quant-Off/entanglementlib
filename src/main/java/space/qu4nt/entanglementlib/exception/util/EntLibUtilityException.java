/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.util;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.EntLibUncheckedException;

import java.io.Serial;

public class EntLibUtilityException extends EntLibUncheckedException {

    @Serial
    private static final long serialVersionUID = -162263763510190731L;

    public <T> EntLibUtilityException(Class<T> i18nTargetClass, @NotNull String key) {
        super(i18nTargetClass, key);
    }

    public <T> EntLibUtilityException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause) {
        super(i18nTargetClass, key, cause);
    }

    public <T> EntLibUtilityException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause, Object... args) {
        super(i18nTargetClass, key, cause, args);
    }
}
