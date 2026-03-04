package space.qu4nt.entanglementlib.security;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeLoader;

public final class EntanglementLibSecurityFacade {

    private EntanglementLibSecurityFacade() {
        throw new UnsupportedOperationException("cannot access");
    }

    public static void initialize(@NotNull EntanglementLibSecurityConfig config) {
        NativeLoader.loadNativeLibrary(config);
        HeuristicArenaFactory.setGlobalArenaMode(config.getArenaMode());
    }
}
