package space.qu4nt.entanglementlib.security.crypto;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.crypto.encode.Base64;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.Function;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@Slf4j
class Base64Test {

    @Test
    @DisplayName("Base64 En/Decode")
    void test() {
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        new NativeSpecContext(System.getenv("ENTLIB_NATIVE_BIN"), "entlib_native_ffi",
                                Function.Callee_Secure_Buffer_Data,
                                Function.Callee_Secure_Buffer_Len,
                                Function.Callee_Secure_Buffer_Free,
                                Function.Caller_Secure_Buffer_Wipe,
                                Function.Base64_encode,
                                Function.Base64_decode),
                        HeuristicArenaFactory.ArenaMode.CONFINED)
        );

        final byte[] plaintext = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer input = scope.allocate(plaintext, true);
            SensitiveDataContainer result = Base64.encode(input);
            final MemorySegment rms = InternalNativeBridge.unwrapMemorySegment(result);

            byte[] actualCipherBytes = rms.toArray(ValueLayout.JAVA_BYTE); // 프로덕션에서 사용 권장 X
            byte[] newACBytes = new byte[actualCipherBytes.length];
            System.arraycopy(actualCipherBytes, 0, newACBytes, 0, actualCipherBytes.length);
            log.info("Encoded: {}", new String(newACBytes, StandardCharsets.UTF_8));

            SensitiveDataContainer decoded = Base64.decode(result);
            MemorySegment decResultOpt = InternalNativeBridge.unwrapMemorySegment(decoded);
            byte[] actualDecBytes = decResultOpt.toArray(ValueLayout.JAVA_BYTE); // 프로덕션에서 사용 권장 X
            byte[] newADCBytes = new byte[actualDecBytes.length];
            System.arraycopy(actualDecBytes, 0, newADCBytes, 0, actualDecBytes.length);
            log.info("Decoded: {}", new String(newADCBytes, StandardCharsets.UTF_8));
        }
    }
}