/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.secure.crypto;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.EntLibException;

import java.io.Serial;

public class EntLibCryptoException extends EntLibException {

    @Serial
    private static final long serialVersionUID = 7785037773312632659L;

    public EntLibCryptoException(Throwable cause) {
        super(cause);
    }

    public <T> EntLibCryptoException(Class<T> i18nTargetClass, @NotNull String key) {
        super(i18nTargetClass, key);
    }

    public <T> EntLibCryptoException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause) {
        super(i18nTargetClass, key, cause);
    }

    public <T> EntLibCryptoException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause, Object... args) {
        super(i18nTargetClass, key, cause, args);
    }
}
