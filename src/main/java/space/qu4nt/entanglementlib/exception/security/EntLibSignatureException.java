/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.security;

import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;

public class EntLibSignatureException extends EntLibSecurityException {

    public <T> EntLibSignatureException(Class<T> clazz, String lowKey) {
        super(LanguageInstanceBased.create(clazz).msg(lowKey));
    }

    public <T> EntLibSignatureException(Class<T> clazz, String lowKey, Throwable cause) {
        super(LanguageInstanceBased.create(clazz).thr(lowKey, cause));
    }

}
