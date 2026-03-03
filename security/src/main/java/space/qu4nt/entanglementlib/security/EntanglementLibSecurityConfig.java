package space.qu4nt.entanglementlib.security;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.util.Nill;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;

@Getter
@Setter
public class EntanglementLibSecurityConfig {

    private NativeSpecContext nativeContext;
    private HeuristicArenaFactory.ArenaMode arenaMode;

    private EntanglementLibSecurityConfig(final NativeSpecContext nativeContext,
                                          final @Nullable HeuristicArenaFactory.ArenaMode arenaMode) {
        this.nativeContext = nativeContext;
        this.arenaMode = arenaMode;
    }

    public static EntanglementLibSecurityConfig create(
            final NativeSpecContext nativeContext,
            final @Nullable HeuristicArenaFactory.ArenaMode arenaMode
    ) {
        return new EntanglementLibSecurityConfig(
                Nill.nullDef(nativeContext, NativeSpecContext::defaults),
                Nill.nullDef(arenaMode, () -> HeuristicArenaFactory.ArenaMode.AUTO)
        );
    }
}
