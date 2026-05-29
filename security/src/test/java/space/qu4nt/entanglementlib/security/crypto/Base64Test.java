package space.qu4nt.entanglementlib.security.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.crypto.encode.Base64;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

// 네이티브 바이너리 경로(ENTLIB_NATIVE_BIN)가 설정된 경우에만 수행되는 통합 테스트
@EnabledIfEnvironmentVariable(named = "ENTLIB_NATIVE_BIN", matches = ".+")
class Base64Test {

    private static final Logger log = LoggerFactory.getLogger(Base64Test.class);

    @Test
    @DisplayName("Base64 En/Decode")
    void test() throws ELIBSecurityProcessException {
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        new NativeSpecContext(System.getenv("ENTLIB_NATIVE_BIN"), "entlib_native_ffi"),
                        HeuristicArenaFactory.ArenaMode.CONFINED)
        );

        final byte[] plaintext = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate(plaintext, true);
            SensitiveDataContainer result = Base64.encode(scope, input);
            final MemorySegment rms = InternalNativeBridge.unwrapMemorySegment(result);

            byte[] actualCipherBytes = rms.toArray(ValueLayout.JAVA_BYTE); // 프로덕션에서 사용 권장 X
            byte[] newACBytes = new byte[actualCipherBytes.length];
            System.arraycopy(actualCipherBytes, 0, newACBytes, 0, actualCipherBytes.length);
            log.info("Encoded: {}", new String(newACBytes, StandardCharsets.UTF_8));

            SensitiveDataContainer decoded = Base64.decode(scope, result);
            MemorySegment decResultOpt = InternalNativeBridge.unwrapMemorySegment(decoded);
            byte[] actualDecBytes = decResultOpt.toArray(ValueLayout.JAVA_BYTE); // 프로덕션에서 사용 권장 X
            byte[] newADCBytes = new byte[actualDecBytes.length];
            System.arraycopy(actualDecBytes, 0, newADCBytes, 0, actualDecBytes.length);
            log.info("Decoded: {}", new String(newADCBytes, StandardCharsets.UTF_8));
        }
    }
}
