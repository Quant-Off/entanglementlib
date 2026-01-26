/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.secure.crypto;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.EntLibException;

import java.io.Serial;

public class EntLibCryptoCipherIllegalIVStateException extends EntLibCryptoCipherProcessException {

    @Serial
    private static final long serialVersionUID = -1818319588140211117L;

    public EntLibCryptoCipherIllegalIVStateException(String message) {
        super(message);
    }

    public <T> EntLibCryptoCipherIllegalIVStateException(Class<T> i18nTargetClass, @NotNull String key) {
        super(i18nTargetClass, key);
    }

    public <T> EntLibCryptoCipherIllegalIVStateException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause) {
        super(i18nTargetClass, key, cause);
    }

    public <T> EntLibCryptoCipherIllegalIVStateException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause, Object... args) {
        super(i18nTargetClass, key, cause, args);
    }
}
