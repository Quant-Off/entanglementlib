package space.qu4nt.entanglementlib.security.crypto;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.entlibnative.Function;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;

import java.nio.charset.StandardCharsets;

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

        final byte[] input = "Hello, World!".getBytes(StandardCharsets.UTF_8);
//        String result = Base64.encode(input);
//
//        log.info("Encode: {}", result);
//        log.info("Decode: {}", new String(Base64.decode(result)));
    }
}