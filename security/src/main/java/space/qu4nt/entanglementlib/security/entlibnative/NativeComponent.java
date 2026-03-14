package space.qu4nt.entanglementlib.security.entlibnative;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.annotations.Only;
import space.qu4nt.entanglementlib.security.entlibnative.info.FunctionInfo;
import space.qu4nt.entanglementlib.security.entlibnative.info.StructInfo;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

/// NOTE: 사용자는 확장되거나 구체화된 entlib-native 바이너리를 제공했을 수 있음. 따라서 이 클래스 형식은 유효
@Getter
public class NativeComponent {

    protected static final List<NativeComponent> LOADED = new ArrayList<>();

    @Only("windows")
    static final NativeComponent OS_SC_VIRTUAL_LOCK = NativeComponent.ofOSFunction(
            FunctionInfo.of("VirtualLock", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
    @Only("windows")
    static final NativeComponent OS_SC_VIRTUAL_UNLOCK = NativeComponent.ofOSFunction(
            FunctionInfo.of("VirtualUnlock", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
    @Only("unix")
    static final NativeComponent OS_SC_MLOCK = NativeComponent.ofOSFunction(
            FunctionInfo.of("mlock", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
    @Only("unix")
    static final NativeComponent OS_SC_MUNLOCK = NativeComponent.ofOSFunction(
            FunctionInfo.of("munlock", ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /// FFI 함수 수행 결과를 받는 구조체 컴포넌트입니다.
    static final NativeComponent STRUCT_ENTLIB_RESULT = NativeComponent.ofStruct(
            StructInfo.of("EntLibResult",
                    "type_id", ValueLayout.JAVA_BYTE,
                    "status", ValueLayout.JAVA_BYTE,
                    "_PADDING", MemoryLayout.paddingLayout(6),
                    "data", ValueLayout.ADDRESS));
    /// Java와 Rust 간의 FFI 통신 표준 구조체 컴포넌트입니다.
    public static final NativeComponent STRUCT_FFI_STANDARD = NativeComponent.ofStruct(
            StructInfo.of("FFIStandard",
                    "ptr", ValueLayout.ADDRESS,
                    "len", ValueLayout.JAVA_BYTE,
                    "is_rust_owned", ValueLayout.JAVA_BOOLEAN));
    /// Java-Owned End Process order 함수 컴포넌트입니다. Java 측 연산 종료 후, Rust에게 메모리 소거를 지시할 때 사용됩니다.
    static final NativeComponent FUNC_JOEP = NativeComponent.ofFunction(
            FunctionInfo.of("joep", STRUCT_ENTLIB_RESULT.getStructInfo().toStructLayout(), STRUCT_FFI_STANDARD.getStructInfo().toStructLayout()));

    /// Base64 인/디코딩 함수 컴포넌트입니다.
    static final NativeComponent FUNC_BASE64_ENCODE;
    static final NativeComponent FUNC_BASE64_DECODE;

    static {
        final FunctionInfo defaultHashFuncLayout = FunctionInfo.of(null, STRUCT_ENTLIB_RESULT.getStructInfo().toStructLayout(), STRUCT_FFI_STANDARD.getStructInfo().toStructLayout(), STRUCT_FFI_STANDARD.getStructInfo().toStructLayout());
        FUNC_BASE64_ENCODE = NativeComponent.ofFunction(FunctionInfo.of("ffi_base64_encode", defaultHashFuncLayout));
        FUNC_BASE64_DECODE = NativeComponent.ofFunction(FunctionInfo.of("ffi_base64_decode", defaultHashFuncLayout));
    }

    /// Hex 인/디코딩 함수 컴포넌트입니다.
    static final NativeComponent FUNC_HEX_ENCODE;
    static final NativeComponent FUNC_HEX_DECODE;

    static {
        final FunctionInfo defaultHashFuncLayout = FunctionInfo.of(null, STRUCT_ENTLIB_RESULT.getStructInfo().toStructLayout(), STRUCT_FFI_STANDARD.getStructInfo().toStructLayout(), STRUCT_FFI_STANDARD.getStructInfo().toStructLayout());
        FUNC_HEX_ENCODE = NativeComponent.ofFunction(FunctionInfo.of("ffi_hex_encode", defaultHashFuncLayout));
        FUNC_HEX_DECODE = NativeComponent.ofFunction(FunctionInfo.of("ffi_hex_decode", defaultHashFuncLayout));
    }

    /// Hash SHA-2, 3 해시 함수 컴포넌트입니다.
    static final NativeComponent FUNC_HASH_SHA2_224;
    static final NativeComponent FUNC_HASH_SHA2_256;
    static final NativeComponent FUNC_HASH_SHA2_384;
    static final NativeComponent FUNC_HASH_SHA2_512;
    static final NativeComponent FUNC_HASH_SHA3_224;
    static final NativeComponent FUNC_HASH_SHA3_256;
    static final NativeComponent FUNC_HASH_SHA3_384;
    static final NativeComponent FUNC_HASH_SHA3_512;
    static final NativeComponent FUNC_HASH_SHA3_224_BITS;
    static final NativeComponent FUNC_HASH_SHA3_256_BITS;
    static final NativeComponent FUNC_HASH_SHA3_384_BITS;
    static final NativeComponent FUNC_HASH_SHA3_512_BITS;
    static final NativeComponent FUNC_HASH_SHA3_SHAKE128;
    static final NativeComponent FUNC_HASH_SHA3_SHAKE256;
    static final NativeComponent FUNC_HASH_SHA3_SHAKE128_BITS;
    static final NativeComponent FUNC_HASH_SHA3_SHAKE256_BITS;

    static {
        final FunctionInfo defaultHashFuncLayout = FunctionInfo.of(null, STRUCT_ENTLIB_RESULT.getStructInfo().toStructLayout(), STRUCT_FFI_STANDARD.getStructInfo().toStructLayout(), STRUCT_FFI_STANDARD.getStructInfo().toStructLayout());
        final FunctionInfo defaultHashBitsFuncLayout = FunctionInfo.of(null, defaultHashFuncLayout).andArg(ValueLayout.JAVA_BYTE).andArg(ValueLayout.JAVA_LONG);
        FUNC_HASH_SHA2_224 = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha2_224", defaultHashFuncLayout));
        FUNC_HASH_SHA2_256 = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha2_256", defaultHashFuncLayout));
        FUNC_HASH_SHA2_384 = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha2_384", defaultHashFuncLayout));
        FUNC_HASH_SHA2_512 = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha2_512", defaultHashFuncLayout));

        FUNC_HASH_SHA3_224 = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha3_224", defaultHashFuncLayout));
        FUNC_HASH_SHA3_256 = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha3_256", defaultHashFuncLayout));
        FUNC_HASH_SHA3_384 = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha3_384", defaultHashFuncLayout));
        FUNC_HASH_SHA3_512 = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha3_512", defaultHashFuncLayout));
        FUNC_HASH_SHA3_224_BITS = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha3_224_bits", defaultHashBitsFuncLayout));
        FUNC_HASH_SHA3_256_BITS = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha3_256_bits", defaultHashBitsFuncLayout));
        FUNC_HASH_SHA3_384_BITS = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha3_384_bits", defaultHashBitsFuncLayout));
        FUNC_HASH_SHA3_512_BITS = NativeComponent.ofFunction(FunctionInfo.of("ffi_sha3_512_bits", defaultHashBitsFuncLayout));

        FUNC_HASH_SHA3_SHAKE128 = NativeComponent.ofFunction(FunctionInfo.of("ffi_shake128", defaultHashFuncLayout));
        FUNC_HASH_SHA3_SHAKE256 = NativeComponent.ofFunction(FunctionInfo.of("ffi_shake256", defaultHashFuncLayout));
        FUNC_HASH_SHA3_SHAKE128_BITS = NativeComponent.ofFunction(FunctionInfo.of("ffi_shake128_bits", defaultHashBitsFuncLayout));
        FUNC_HASH_SHA3_SHAKE256_BITS = NativeComponent.ofFunction(FunctionInfo.of("ffi_shake256_bits", defaultHashBitsFuncLayout));
    }

    @Getter
    private final boolean isOsDefault;
    private final FunctionInfo functionInfo;
    private final StructInfo structInfo;

    private NativeComponent(final boolean isOsDefault, final FunctionInfo functionInfo, final StructInfo structInfo) {
        this.isOsDefault = isOsDefault;
        this.functionInfo = functionInfo;
        this.structInfo = structInfo;
    }

    public static NativeComponent ofOSFunction(final @NotNull FunctionInfo functionInfo) {
        NativeComponent r = new NativeComponent(true, functionInfo, null);
        LOADED.add(r);
        return r;
    }

    public static NativeComponent ofOSStruct(final @NotNull StructInfo structInfo) {
        NativeComponent r = new NativeComponent(true, null, structInfo);
        LOADED.add(r);
        return r;
    }

    public static NativeComponent ofFunction(final @NotNull FunctionInfo functionInfo) {
        NativeComponent r = new NativeComponent(false, functionInfo, null);
        LOADED.add(r);
        return r;
    }

    // TODO: Struct Info 클래스 결국 만들어야 겠다...
    public static NativeComponent ofStruct(final @NotNull StructInfo structInfo) {
        NativeComponent r = new NativeComponent(false, null, structInfo);
        LOADED.add(r);
        return r;
    }

    public static NativeComponent[] chain(NativeComponent[] source, NativeComponent[]... additional) {
        int size = source.length;
        for (NativeComponent[] specs : additional) {
            size += specs.length;
        }

        NativeComponent[] result = new NativeComponent[size];

        System.arraycopy(source, 0, result, 0, source.length);
        int currentPosition = source.length;

        for (NativeComponent[] specs : additional) {
            System.arraycopy(specs, 0, result, currentPosition, specs.length);
            currentPosition += specs.length;
        }

        return result;
    }

    public boolean isStructComponent() {
        return functionInfo == null && structInfo != null;
    }
}
