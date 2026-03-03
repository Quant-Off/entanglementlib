package space.qu4nt.entanglementlib.core;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.core.ELIBCoreIllegalArgumentException;
import space.qu4nt.entanglementlib.core.i18n.EntanglementLibCoreI18n;

import java.util.Locale;

public final class EntanglementLibCoreContext {

    @Getter
    private static volatile boolean initialized = false;

    private EntanglementLibCoreContext() {
        throw new UnsupportedOperationException("cannot access");
    }

    public static synchronized void initialize(final @NotNull Locale locale, @Nullable String userResourceBasename)
            throws ELIBCoreIllegalArgumentException {
        if (!initialized) {
            EntanglementLibCoreI18n.initialize(locale, userResourceBasename);
            initialized = true;
        }
    }
}
