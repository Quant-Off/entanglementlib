package space.qu4nt.entanglementlib.security.entlibnative;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.jetbrains.annotations.NotNull;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

/// NOTE: 사용자는 확장되거나 구체화된 entlib-native 바이너리를 제공했을 수 있음. 따라서 이 클래스 형식은 유효
@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class Function {

    protected static final List<Function> LOADED = new ArrayList<>();

    // 보안 버퍼 엔드포인트
    // 피호출자 할당
    public static final Function Callee_Secure_Buffer_Data = Function.of("entlib_secure_buffer_data", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function Callee_Secure_Buffer_Len = Function.of("entlib_secure_buffer_len", ValueLayout.JAVA_LONG, ValueLayout.ADDRESS);
    public static final Function Callee_Secure_Buffer_Free = Function.ofVoid("entlib_secure_buffer_free", ValueLayout.ADDRESS); // 보안 작업에서는 공통적으로 사용
    // 호출자 할당
    public static final Function Caller_Secure_Buffer_Wipe = Function.ofVoid("entanglement_secure_wipe", ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);

    // 데이터 상호 작용을 위한 엔드포인트
    public static final Function SecureBuffer_Data = Function.of("entlib_secure_buffer_data", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SecureBuffer_Len = Function.of("entlib_secure_buffer_len", ValueLayout.JAVA_LONG, ValueLayout.ADDRESS);
    public static final Function SecureBuffer_Free = Function.ofVoid("entlib_secure_buffer_free", ValueLayout.ADDRESS);
    public static final Function SecureBuffer_View = Function.of("entlib_secure_buffer_view",
            MemoryLayout.structLayout(
                    ValueLayout.ADDRESS.withName("data"),
                    ValueLayout.JAVA_LONG.withName("len")
            ),
            ValueLayout.ADDRESS
    );
    public static final Function SecureBuffer_CopyAndFree = Function.of("entlib_secure_buffer_copy_and_free", ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG
    );

    // Base64 엔드포인트
    public static final Function Base64_encode = Function.of("entlib_b64_encode_caller_alloc", ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function Base64_decode = Function.of("entlib_b64_decode_caller_alloc", ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG); // todo; err_flag 파라미터 추가 확인 필요

    // Hash 엔드포인트
    // SHA2
    public static final Function SHA2_224_New = Function.of("entlib_sha224_new", ValueLayout.ADDRESS);
    public static final Function SHA2_224_Update = Function.of("entlib_sha224_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA2_224_Finalize = Function.of("entlib_sha224_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SHA2_224_Free = Function.ofVoid("entlib_sha224_free", ValueLayout.ADDRESS);

    public static final Function SHA2_256_New = Function.of("entlib_sha256_new", ValueLayout.ADDRESS);
    public static final Function SHA2_256_Update = Function.of("entlib_sha256_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA2_256_Finalize = Function.of("entlib_sha256_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SHA2_256_Free = Function.ofVoid("entlib_sha256_free", ValueLayout.ADDRESS);

    public static final Function SHA2_384_New = Function.of("entlib_sha384_new", ValueLayout.ADDRESS);
    public static final Function SHA2_384_Update = Function.of("entlib_sha384_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA2_384_Finalize = Function.of("entlib_sha384_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SHA2_384_Free = Function.ofVoid("entlib_sha384_free", ValueLayout.ADDRESS);

    public static final Function SHA2_512_New = Function.of("entlib_sha512_new", ValueLayout.ADDRESS);
    public static final Function SHA2_512_Update = Function.of("entlib_sha512_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA2_512_Finalize = Function.of("entlib_sha512_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SHA2_512_Free = Function.ofVoid("entlib_sha512_free", ValueLayout.ADDRESS);

    // SHA3
    public static final Function SHA3_224_New = Function.of("entlib_sha3_224_new", ValueLayout.ADDRESS);
    public static final Function SHA3_224_Update = Function.of("entlib_sha3_224_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA3_224_Finalize = Function.of("entlib_sha3_224_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SHA3_224_Free = Function.ofVoid("entlib_sha3_224_free", ValueLayout.ADDRESS);

    public static final Function SHA3_256_New = Function.of("entlib_sha3_256_new", ValueLayout.ADDRESS);
    public static final Function SHA3_256_Update = Function.of("entlib_sha3_256_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA3_256_Finalize = Function.of("entlib_sha3_256_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SHA3_256_Free = Function.ofVoid("entlib_sha3_256_free", ValueLayout.ADDRESS);

    public static final Function SHA3_384_New = Function.of("entlib_sha3_384_new", ValueLayout.ADDRESS);
    public static final Function SHA3_384_Update = Function.of("entlib_sha3_384_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA3_384_Finalize = Function.of("entlib_sha3_384_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SHA3_384_Free = Function.ofVoid("entlib_sha3_384_free", ValueLayout.ADDRESS);

    public static final Function SHA3_512_New = Function.of("entlib_sha3_512_new", ValueLayout.ADDRESS);
    public static final Function SHA3_512_Update = Function.of("entlib_sha3_512_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA3_512_Finalize = Function.of("entlib_sha3_512_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function SHA3_512_Free = Function.ofVoid("entlib_sha3_512_free", ValueLayout.ADDRESS);

    public static final Function SHA3_SHAKE128_New = Function.of("entlib_sha3_shake128_new", ValueLayout.ADDRESS);
    public static final Function SHA3_SHAKE128_Update = Function.of("entlib_sha3_shake128_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA3_SHAKE128_Finalize = Function.of("entlib_sha3_shake128_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA3_SHAKE128_Free = Function.ofVoid("entlib_sha3_shake128_free", ValueLayout.ADDRESS);

    public static final Function SHA3_SHAKE256_New = Function.of("entlib_sha3_shake256_new", ValueLayout.ADDRESS);
    public static final Function SHA3_SHAKE256_Update = Function.of("entlib_sha3_shake256_update", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA3_SHAKE256_Finalize = Function.of("entlib_sha3_shake256_finalize", ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG);
    public static final Function SHA3_SHAKE256_Free = Function.ofVoid("entlib_sha3_shake256_free", ValueLayout.ADDRESS);

    // RNG 엔드포인트
    public static final Function RNG_HW_Generate = Function.of("entlib_rng_hw_generate", ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS);
    public static final Function RNG_HW_Next_Generate = Function.of("entlib_rng_hw_next_generate", ValueLayout.JAVA_BYTE, ValueLayout.ADDRESS);
    public static final Function RNG_ANU_Generate = Function.of("entlib_rng_anu_generate", ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS);
    public static final Function RNG_MIXED_New_With_Strategy = Function.of("entlib_rng_mixed_new_with_strategy", ValueLayout.ADDRESS, ValueLayout.JAVA_BYTE, ValueLayout.ADDRESS);
    public static final Function RNG_MIXED_New = Function.of("entlib_rng_mixed_new", ValueLayout.ADDRESS, ValueLayout.ADDRESS);
    public static final Function RNG_MIXED_Generate = Function.of("entlib_rng_mixed_generate", ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS);
    public static final Function RNG_MIXED_Free = Function.ofVoid("entlib_rng_mixed_free", ValueLayout.ADDRESS);

    // ChaCha20 엔드포인트
    public static final Function ChaCha20_Process = Function.of("process_chacha20_ffi", ValueLayout.ADDRESS,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG);
    public static final Function ChaCha20_Poly1305_MAC_Generate = Function.of("generate_poly1305_ffi", ValueLayout.ADDRESS,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG);
    public static final Function ChaCha20_Poly1305_Encrypt = Function.of("chacha20_poly1305_encrypt_ffi", ValueLayout.ADDRESS,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG);
    public static final Function ChaCha20_Poly1305_Decrypt = Function.of("chacha20_poly1305_decrypt_ffi", ValueLayout.ADDRESS,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS,
            ValueLayout.JAVA_LONG);

    private final @NotNull String functionName;
    private final FunctionDescriptor descriptor;

    public static Function of(final @NotNull String functionName, MemoryLayout returnType, MemoryLayout... args) {
        Function r = new Function(functionName, FunctionDescriptor.of(returnType, args));
        LOADED.add(r);
        return r;
    }

    public static Function ofVoid(final @NotNull String functionName, MemoryLayout... args) {
        Function r = new Function(functionName, FunctionDescriptor.ofVoid(args));
        LOADED.add(r);
        return r;
    }

    public static Function[] chain(Function[] source, Function[]... additional) {
        int size = source.length;
        for (Function[] specs : additional) {
            size += specs.length;
        }

        Function[] result = new Function[size];

        System.arraycopy(source, 0, result, 0, source.length);
        int currentPosition = source.length;

        for (Function[] specs : additional) {
            System.arraycopy(specs, 0, result, currentPosition, specs.length);
            currentPosition += specs.length;
        }

        return result;
    }

    public static Function[] withCallerSecureBuffer() {
        return new Function[]{
                Callee_Secure_Buffer_Data,
                Callee_Secure_Buffer_Len,
                Callee_Secure_Buffer_Free,
                Caller_Secure_Buffer_Wipe
        };
    }

    public static Function[] withCalleeSecureBuffer() {
        return new Function[]{
                SecureBuffer_Data,
                SecureBuffer_Len,
                SecureBuffer_Free,
                SecureBuffer_View,
                SecureBuffer_CopyAndFree
        };
    }

    public static Function[] withRNG() {
        return new Function[]{
                RNG_HW_Generate,
                RNG_HW_Next_Generate,
                RNG_ANU_Generate,
                RNG_MIXED_New_With_Strategy,
                RNG_MIXED_New,
                RNG_MIXED_Generate,
                RNG_MIXED_Free
        };
    }

    public static Function[] withHash(boolean sha2) {
        if (sha2)
            return new Function[]{
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
                    SHA2_512_Free
            };
        return new Function[] {
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
                SHA3_SHAKE256_Free
        };
    }

    public static Function[] withChaCha20() {
        return new Function[]{
                ChaCha20_Process,
                ChaCha20_Poly1305_MAC_Generate,
                ChaCha20_Poly1305_Encrypt,
                ChaCha20_Poly1305_Decrypt
        };
    }
}
