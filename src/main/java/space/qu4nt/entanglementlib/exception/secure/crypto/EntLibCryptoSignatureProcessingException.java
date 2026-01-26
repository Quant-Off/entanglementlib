/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.secure.crypto;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.exception.EntLibException;

import java.io.Serial;

public class EntLibCryptoSignatureProcessingException extends EntLibException {

    @Serial
    private static final long serialVersionUID = 951548478208181292L;

    public EntLibCryptoSignatureProcessingException(String message) {
        super(message);
    }

    public EntLibCryptoSignatureProcessingException(String message, Throwable cause) {
        super(message, cause);
    }

    public <T> EntLibCryptoSignatureProcessingException(Class<T> i18nTargetClass, @NotNull String key) {
        super(i18nTargetClass, key);
    }

    public <T> EntLibCryptoSignatureProcessingException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause) {
        super(i18nTargetClass, key, cause);
    }

    public <T> EntLibCryptoSignatureProcessingException(Class<T> i18nTargetClass, @NotNull String key, Throwable cause, Object... args) {
        super(i18nTargetClass, key, cause, args);
    }
}
