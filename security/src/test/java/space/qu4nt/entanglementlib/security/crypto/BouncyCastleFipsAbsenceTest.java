package space.qu4nt.entanglementlib.security.crypto;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

// bc-fips 는 compileOnly 이므로 배포 환경에 없을 수 있다. 부재 상황을 클래스로더로 재현해
// NoClassDefFoundError 가 아닌 명확한 예외가 나오는지, 실패 시 레지스트리가 오염되지 않는지 검증한다
@DisplayName("bc-fips 부재 시 동작 검증(격리 클래스로더)")
class BouncyCastleFipsAbsenceTest {

    private static final String PROVIDERS = "space.qu4nt.entanglementlib.security.provider.CryptoProviders";
    private static final String CONFIG = "space.qu4nt.entanglementlib.security.provider.CryptoProviderConfig";
    private static final String BACKEND = "space.qu4nt.entanglementlib.security.provider.CryptoBackend";
    private static final String EXPECTED_EXCEPTION =
            "space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException";

    @Test
    @DisplayName("bc-fips 부재 시 BC 백엔드 선택은 명확한 예외로 거부된다")
    void bcBackendRejectedWhenModuleAbsent() throws Exception {
        try (URLClassLoader loader = newBcHidingClassLoader()) {
            final Class<?> providers = Class.forName(PROVIDERS, true, loader);
            final Class<?> config = Class.forName(CONFIG, true, loader);
            final Object bcDefaults = config.getMethod("bouncyCastleFipsDefaults").invoke(null);
            final Method install = providers.getMethod("install", config);

            final InvocationTargetException thrown =
                    assertThrows(InvocationTargetException.class, () -> install.invoke(null, bcDefaults));
            assertEquals(EXPECTED_EXCEPTION, thrown.getCause().getClass().getName(),
                    "모듈 부재는 NoClassDefFoundError 가 아니라 라이브러리 예외로 보고되어야 합니다.");
            assertTrue(thrown.getCause().getMessage().contains("bc-fips"),
                    "예외 메시지가 누락된 아티팩트를 지목해야 합니다.");
        }
    }

    @Test
    @DisplayName("설치 실패 시 레지스트리는 반쪽 상태가 되지 않는다")
    void failedInstallLeavesRegistryUntouched() throws Exception {
        try (URLClassLoader loader = newBcHidingClassLoader()) {
            final Class<?> providers = Class.forName(PROVIDERS, true, loader);
            final Class<?> config = Class.forName(CONFIG, true, loader);
            final Class<?> backend = Class.forName(BACKEND, true, loader);

            // 다이제스트·인코딩·AEAD 는 해석에 성공하고 난수만 실패하는 구성
            final Object builder = config.getMethod("builder").invoke(null);
            final Class<?> builderType = builder.getClass();
            final Object bcValue = backend.getField("BOUNCY_CASTLE_FIPS").get(null);
            builderType.getMethod("useVerifiedProviders").invoke(builder);
            builderType.getMethod("random", backend).invoke(builder, bcValue);
            final Object mixed = builderType.getMethod("build").invoke(builder);

            assertThrows(InvocationTargetException.class,
                    () -> providers.getMethod("install", config).invoke(null, mixed));

            // 실패 전 상태(정적 초기화가 설치한 검증된 JDK 기본값)가 그대로 남아야 한다
            assertEquals("JDK JCA (검증)", backendNameOf(providers, "digest"));
            assertEquals("JDK 표준 (검증)", backendNameOf(providers, "encoding"));
            assertEquals("JDK SecureRandom (검증)", backendNameOf(providers, "random"));
        }
    }

    private static @NotNull String backendNameOf(final Class<?> providers, final String feature) throws Exception {
        final Object provider = providers.getMethod(feature).invoke(null);
        return (String) provider.getClass().getMethod("backendName").invoke(provider);
    }

    /// 현재 테스트 클래스패스에서 bc-fips 아티팩트를 제거하고 `org.bouncycastle` 적재를 차단하는 로더
    private static URLClassLoader newBcHidingClassLoader() throws Exception {
        final List<URL> urls = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            if (entry.isBlank() || entry.contains("bc-fips")) continue;
            urls.add(Path.of(entry).toUri().toURL());
        }
        assertFalse(urls.isEmpty(), "테스트 클래스패스를 확인할 수 없습니다.");
        return new BcHidingClassLoader(urls.toArray(URL[]::new));
    }

    private static final class BcHidingClassLoader extends URLClassLoader {

        private BcHidingClassLoader(final URL[] urls) {
            super("bc-hiding", urls, ClassLoader.getPlatformClassLoader());
        }

        @Override
        protected Class<?> loadClass(final String name, final boolean resolve) throws ClassNotFoundException {
            if (name.startsWith("org.bouncycastle."))
                throw new ClassNotFoundException(name + " (테스트가 의도적으로 차단)");
            return super.loadClass(name, resolve);
        }
    }
}
