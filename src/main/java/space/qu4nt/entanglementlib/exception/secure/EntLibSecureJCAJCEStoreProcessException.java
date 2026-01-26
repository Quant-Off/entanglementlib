/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.secure;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.EntLibException;

import java.io.Serial;

public class EntLibSecureJCAJCEStoreProcessException extends EntLibException {

    @Serial
    private static final long serialVersionUID = -1891654898835144441L;

    public EntLibSecureJCAJCEStoreProcessException(Throwable cause) {
        super(cause);
    }

    public <T> EntLibSecureJCAJCEStoreProcessException(Class<T> i18nTargetClass, @NotNull String key) {
        super(i18nTargetClass, key);
    }

    public <T> EntLibSecureJCAJCEStoreProcessException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause) {
        super(i18nTargetClass, key, cause);
    }

    public <T> EntLibSecureJCAJCEStoreProcessException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause, Object... args) {
        super(i18nTargetClass, key, cause, args);
    }
}
