package space.qu4nt.entanglementlib.security;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeLoader;
import space.qu4nt.entanglementlib.security.provider.CryptoProviderConfig;
import space.qu4nt.entanglementlib.security.provider.CryptoProviders;

public final class EntanglementLibSecurityFacade {

    private static final Logger log = LoggerFactory.getLogger(EntanglementLibSecurityFacade.class);

    private EntanglementLibSecurityFacade() {
        throw new UnsupportedOperationException("cannot access");
    }

    public static void initialize(@NotNull EntanglementLibSecurityConfig config) {
        final CryptoProviderConfig providerConfig = config.getCryptoProviderConfig();

        // 검증 전용 모드(어떤 기능도 네이티브를 쓰지 않음)에서는 미검증 네이티브 바이너리를 로드하지 않음
        if (providerConfig.requiresNative()) {
            NativeLoader.loadNativeLibrary(config); // TODO: entlib-native 기본 로더 로직 추가
        } else {
            log.info("검증 공급자 전용 구성이 감지되어 entlib-native 바이너리 로드를 생략합니다.");
        }

        HeuristicArenaFactory.setGlobalArenaMode(config.getArenaMode());
        CryptoProviders.install(providerConfig);
    }
}
