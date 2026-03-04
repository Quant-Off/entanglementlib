package space.qu4nt.entanglementlib.security.entlibnative;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

import static space.qu4nt.entanglementlib.security.entlibnative.Function.*;

@Getter
@Setter
public class NativeSpecContext {

    private String nativeDirName;
    private String nativeFilename;
    private Set<Function> functions;

    public NativeSpecContext(String nativeDirName, String nativeFilename, Set<Function> functions) {
        this.nativeDirName = nativeDirName;
        this.nativeFilename = nativeFilename;
        this.functions = functions;
    }

    public NativeSpecContext(String nativeDirName, String nativeFilename, Function... functions) {
        this.nativeDirName = nativeDirName;
        this.nativeFilename = nativeFilename;
        this.functions = Set.of(functions);
    }

    public static NativeSpecContext defaults() {
        return new NativeSpecContext("/native", "entlib_native_ffi", Set.of(
                Callee_Secure_Buffer_Data,
                Callee_Secure_Buffer_Len,
                Callee_Secure_Buffer_Free,
                Caller_Secure_Buffer_Wipe,
                SecureBuffer_Data,
                SecureBuffer_Len,
                SecureBuffer_Free,
                SecureBuffer_View,
                SecureBuffer_CopyAndFree,
                Base64_encode,
                Base64_decode,
                SHA2_224_New,
                SHA2_224_Update,
                SHA2_224_Finalize,
                SHA2_224_Free,
                SHA2_256_New,
                SHA2_256_Update,
                SHA2_256_Finalize,
                SHA2_256_Free,
                SHA2_384_New,
                SHA2_384_Update,
                SHA2_384_Finalize,
                SHA2_384_Free,
                SHA2_512_New,
                SHA2_512_Update,
                SHA2_512_Finalize,
                SHA2_512_Free,
                SHA3_224_New,
                SHA3_224_Update,
                SHA3_224_Finalize,
                SHA3_224_Free,
                SHA3_256_New,
                SHA3_256_Update,
                SHA3_256_Finalize,
                SHA3_256_Free,
                SHA3_384_New,
                SHA3_384_Update,
                SHA3_384_Finalize,
                SHA3_384_Free,
                SHA3_512_New,
                SHA3_512_Update,
                SHA3_512_Finalize,
                SHA3_512_Free,
                SHA3_SHAKE128_New,
                SHA3_SHAKE128_Update,
                SHA3_SHAKE128_Finalize,
                SHA3_SHAKE128_Free,
                SHA3_SHAKE256_New,
                SHA3_SHAKE256_Update,
                SHA3_SHAKE256_Finalize,
                SHA3_SHAKE256_Free,
                RNG_HW_Generate,
                RNG_HW_Next_Generate,
                RNG_ANU_Generate,
                RNG_MIXED_New_With_Strategy,
                RNG_MIXED_New,
                RNG_MIXED_Generate,
                RNG_MIXED_Free,
                ChaCha20_Process,
                ChaCha20_Poly1305_MAC_Generate,
                ChaCha20_Poly1305_Encrypt,
                ChaCha20_Poly1305_Decrypt
        ));
    }
}
