/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;

/**
 * 얽힘 라이브러리의 몇 가지 기능을 외부에서 즉시 호출할 수도 있지만
 * 이 경우 정적 블록에 대한 메모리 할당 및 그에 상응하는 작업의 시간 복잡도가
 * 증가합니다. 이를 해결하기 위해 만들어진 내부 로딩 부트스트랩 클래스입니다.
 * <p>
 * 이 클래스가 내부에서 사용되는 경우는 전달받은 외부 프로젝트(호출자)의 이름을
 * 사용하는 때 이외엔 없으며, 호출되어서도 안 됩니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
@Getter
@Setter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public final class EntanglementLibBootstrap {

    static {
        log.debug("얽힘 라이브러리(EntanglementLib) 등록");
    }

    @ApiStatus.Internal
    private @NotNull String projectName;

    @ExternalPattern
    public static EntanglementLibBootstrap registerEntanglementLib(@NotNull String projectName, boolean setBCProviders) {
        if (setBCProviders)
            InternalFactory.registerInternalEntanglementLib();
        return new EntanglementLibBootstrap(projectName);
    }

    @ExternalPattern
    public @NotNull SecureRandom getSafeRandom() {
        return InternalFactory.getSafeRandom();
    }

    @ApiStatus.Internal
    public static void providerInformation() throws IOException {
        Map<String, Map<String, List<String>>> providerInfo = new LinkedHashMap<>();

        for (Provider provider : Security.getProviders()) {
            if (provider == null || provider.getName() == null) continue;

            String providerName = provider.getName();
            Map<String, List<String>> services = new TreeMap<>();

            for (Provider.Service service : provider.getServices()) {
                String type = service.getType();
                String algorithm = service.getAlgorithm();

                StringBuilder algoDetails = new StringBuilder(algorithm);

                try {
                    Field attrField = service.getClass().getDeclaredField("attributes");
                    attrField.setAccessible(true);
                    @SuppressWarnings("unchecked")
                    Map<Object, Object> map = (Map<Object, Object>) attrField.get(service);
                    if (map != null) {
                        map.forEach((k, v) -> {
                            if (!"Software".equals(v)) {
//                                algoDetails.append("\n    - ").append(k).append(": ").append(v);
                            }
                        });
                    }
                } catch (Exception _) {
                }

                services.computeIfAbsent(type, k -> new ArrayList<>()).add(algoDetails.toString());
            }
            providerInfo.put(providerName, services);
        }

        StringBuilder stringTower = new StringBuilder();
        providerInfo.forEach((pName, services) -> {
            stringTower.append("공급자: ").append(pName).append("\n");
            services.forEach((type, algos) -> {
                stringTower.append("- ").append(type).append("\n");
                for (String algo : algos) {
                    stringTower.append("  - ").append(algo).append("\n");
                }
            });
            stringTower.append("\n");
        });

        Files.writeString(Paths.get(InternalFactory.envEntanglementPublicDir()).resolve("security-providers.txt"), stringTower.toString(), StandardCharsets.UTF_8);
    }

    @ApiStatus.Internal
    static void main() throws IOException {
        InternalFactory.setupSecurityProviders();
        providerInformation();
    }
}
