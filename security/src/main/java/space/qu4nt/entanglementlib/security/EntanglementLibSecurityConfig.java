package space.qu4nt.entanglementlib.security;

import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.util.Nill;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;
import space.qu4nt.entanglementlib.security.provider.CryptoProviderConfig;

public class EntanglementLibSecurityConfig {

    private NativeSpecContext nativeContext;
    private HeuristicArenaFactory.ArenaMode arenaMode;
    private CryptoProviderConfig cryptoProviderConfig;

    private EntanglementLibSecurityConfig(final NativeSpecContext nativeContext,
                                          final @Nullable HeuristicArenaFactory.ArenaMode arenaMode,
                                          final @Nullable CryptoProviderConfig cryptoProviderConfig) {
        this.nativeContext = nativeContext;
        this.arenaMode = arenaMode;
        this.cryptoProviderConfig = cryptoProviderConfig;
    }

    public static EntanglementLibSecurityConfig create(
            final NativeSpecContext nativeContext,
            final @Nullable HeuristicArenaFactory.ArenaMode arenaMode
    ) {
        return create(nativeContext, arenaMode, null);
    }

    public static EntanglementLibSecurityConfig create(
            final NativeSpecContext nativeContext,
            final @Nullable HeuristicArenaFactory.ArenaMode arenaMode,
            final @Nullable CryptoProviderConfig cryptoProviderConfig
    ) {
        return new EntanglementLibSecurityConfig(
                Nill.nullDef(nativeContext, NativeSpecContext::defaults),
                Nill.nullDef(arenaMode, () -> HeuristicArenaFactory.ArenaMode.AUTO),
                Nill.nullDef(cryptoProviderConfig, CryptoProviderConfig::verifiedDefaults)
        );
    }

    public NativeSpecContext getNativeContext() {
        return nativeContext;
    }

    public void setNativeContext(NativeSpecContext nativeContext) {
        this.nativeContext = nativeContext;
    }

    public HeuristicArenaFactory.ArenaMode getArenaMode() {
        return arenaMode;
    }

    public void setArenaMode(HeuristicArenaFactory.ArenaMode arenaMode) {
        this.arenaMode = arenaMode;
    }

    public CryptoProviderConfig getCryptoProviderConfig() {
        return cryptoProviderConfig;
    }

    public void setCryptoProviderConfig(CryptoProviderConfig cryptoProviderConfig) {
        this.cryptoProviderConfig = Nill.nullDef(cryptoProviderConfig, CryptoProviderConfig::verifiedDefaults);
    }
}
