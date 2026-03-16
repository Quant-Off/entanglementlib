package space.qu4nt.entanglementlib.security.entlibnative;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityCritical;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityNativeCritical;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.util.Map;
import java.util.Objects;

/// 내부적으로 핫 패스 최적화를 위한 핵심 [java.lang.constant.Constable] 정적 캐시를 수행하기 위한 클래스를 정의한 클래스
///
/// 개별 클래스는 지연 로딩 패턴을 사용
///
/// TODO: 특정 constable은 entlib-native 바이너리가 없으면 사용 불가능하도록
@ApiStatus.Internal
public final class ConstableFactory {

    static final Map<NativeComponent, MethodHandle> withoutOSMethodHandles = NativeLinker.withoutOSMethodHandles;

    public static @Nullable MethodHandle getImportedComponentMethodHandle(final @NotNull NativeComponent component) {
        if (withoutOSMethodHandles.containsKey(component))
            return withoutOSMethodHandles.get(component);
        return null;
    }

    public static void processImportedComponentMethodHandle(final @NotNull MethodHandle handle, final HandleProcessConsumer<MethodHandle> process) throws ELIBSecurityProcessException {
        if (handle == null) return;
        try {
            Objects.requireNonNull(process).accept(handle);
        } catch (Throwable e) {
            throw new ELIBSecurityProcessException("네이티브 함수 핸들링 작업 중 예외가 발생했습니다!", e);
        }
    }

    public static void processImportedComponentMethodHandle(final @NotNull NativeComponent component, final HandleProcessConsumer<MethodHandle> process) throws ELIBSecurityProcessException {
        @Nullable MethodHandle handle = getImportedComponentMethodHandle(component);
        if (handle == null) return;
        try {
            Objects.requireNonNull(process).accept(handle);
        } catch (Throwable e) {
            throw new ELIBSecurityProcessException("네이티브 함수 '" + component.getFunctionInfo().getFunctionName() + "' 핸들링 작업 중 예외가 발생했습니다!", e);
        }
    }

    static <T extends MethodHandle> Object wrapInvokeGlobal(final T o, final Object... val) throws ELIBSecurityProcessException {
        try {
            return o.invokeExact(val);
        } catch (Throwable e) {
            throw new ELIBSecurityProcessException("글로벌 네이티브 함수 '" + o.toString() + "' 실행 중 예외가 발생했습니다!", e);
        }
    }

    static <T extends MethodHandle, A> NativeProcessResult<A> wrapInvoke(final T o, final @Nullable Class<A> additionalDataType, final Object... val) throws ELIBSecurityProcessException {
        try {
            MemorySegment resultPtr = (MemorySegment) o.invokeExact(val);
            return new NativeProcessResult<>(new FFIStructEntLibResult<>(
                    (byte) Std.STRUCT_ENTLIB_RESULT_type_id.get(resultPtr),
                    (byte) Std.STRUCT_ENTLIB_RESULT_status.get(resultPtr),
                    additionalDataType == null ? null : additionalDataType.cast(Std.STRUCT_ENTLIB_RESULT_data.get(resultPtr))
            ));
        } catch (Throwable e) {
            if (e.getClass().equals(ClassCastException.class) && additionalDataType != null)
                throw new ELIBSecurityProcessException("네이티브 함수 '" + o + "'의 data 값을 '" +
                        additionalDataType.getCanonicalName() + "' 타입으로 캐스팅 할 수 없습니다!", e);
            throw new ELIBSecurityProcessException("네이티브 함수 '" + o.toString() + "' 실행 중 예외가 발생했습니다!", e);
        }
    }

    static <T extends MethodHandle, A> Object wrapInvoke(final T o, final @Nullable Class<A> additionalDataType, final @NotNull String additionalLog, final Object... val) throws ELIBSecurityProcessException {
        try {
            MemorySegment resultPtr = (MemorySegment) o.invokeExact(val);
            return new NativeProcessResult<>(new FFIStructEntLibResult<>(
                    (byte) Std.STRUCT_ENTLIB_RESULT_type_id.get(resultPtr),
                    (byte) Std.STRUCT_ENTLIB_RESULT_status.get(resultPtr),
                    additionalDataType == null ? null : additionalDataType.cast(Std.STRUCT_ENTLIB_RESULT_data.get(resultPtr))
            ));
        } catch (Throwable e) {
            if (e.getClass().equals(ClassCastException.class) && additionalDataType != null)
                throw new ELIBSecurityProcessException("네이티브 함수 '" + o + "'의 data 값을 '" +
                        additionalDataType.getCanonicalName() + "' 타입으로 캐스팅 할 수 없습니다!", e);
            throw new ELIBSecurityProcessException("네이티브 함수 '" + o.toString() + "' 실행 중 예외가 발생했습니다! 상세: " + additionalLog, e);
        }
    }

    public static final class Custom {
//        static final MethodHandle FUNC_SUM_GET;

        static {
//            FUNC_SUM_GET = entlibMethodHandles.get(NativeComponent.FUNC_SUM_GET);
        }
    }

    /// FFI 경계 호출에서 기본적으로(자주) 사용되는 컴포넌트의 핸들러를 정의한 클래스입니다.
    public static final class Std {
        // os std
        static final MethodHandle OS_SC_VIRTUAL_LOCK;
        static final MethodHandle OS_SC_VIRTUAL_UNLOCK;
        static final MethodHandle OS_SC_MLOCK;
        static final MethodHandle OS_SC_MUNLOCK;

        // 네이티브 함수 결과 래핑
        static final VarHandle STRUCT_ENTLIB_RESULT_type_id;
        static final VarHandle STRUCT_ENTLIB_RESULT_status;
        static final VarHandle STRUCT_ENTLIB_RESULT_data;

        // JO 패턴의 경우, 작업 종료 시 이 핸들러를 사용하여 Rust 에게 메모리 할당 해제 지시
        static final MethodHandle FUNC_JOEP;

        // JO 패턴의 경우, 데이터를 래핑하는 데 이 핸들러를 사용 (Rust로 전송)
        public static final VarHandle STRUCT_FFI_STANDARD_ptr;
        public static final VarHandle STRUCT_FFI_STANDARD_len;
        public static final VarHandle STRUCT_FFI_STANDARD_is_rust_owned;

        static {
            // OSStd
            final Map<NativeComponent, MethodHandle> osDefaultMethodHandles = NativeLinker.osDefaultMethodHandles;
            OS_SC_VIRTUAL_LOCK = osDefaultMethodHandles.get(NativeComponent.OS_SC_VIRTUAL_LOCK);
            OS_SC_VIRTUAL_UNLOCK = osDefaultMethodHandles.get(NativeComponent.OS_SC_VIRTUAL_UNLOCK);
            OS_SC_MLOCK = osDefaultMethodHandles.get(NativeComponent.OS_SC_MLOCK);
            OS_SC_MUNLOCK = osDefaultMethodHandles.get(NativeComponent.OS_SC_MUNLOCK);

            // EntLibResult
            final StructLayout entlibResult = NativeComponent.STRUCT_ENTLIB_RESULT.getStructInfo().toStructLayout();
            STRUCT_ENTLIB_RESULT_type_id = entlibResult.varHandle(MemoryLayout.PathElement.groupElement("type_id"));
            STRUCT_ENTLIB_RESULT_status = entlibResult.varHandle(MemoryLayout.PathElement.groupElement("status"));
            STRUCT_ENTLIB_RESULT_data = entlibResult.varHandle(MemoryLayout.PathElement.groupElement("data"));

            // JOEP order
            FUNC_JOEP = getImportedComponentMethodHandle(NativeComponent.FUNC_JOEP);

            // FFIStandard
            final StructLayout ffiStandard = NativeComponent.STRUCT_FFI_STANDARD.getStructInfo().toStructLayout();
            STRUCT_FFI_STANDARD_ptr = ffiStandard.varHandle(MemoryLayout.PathElement.groupElement("ptr"));
            STRUCT_FFI_STANDARD_len = ffiStandard.varHandle(MemoryLayout.PathElement.groupElement("len"));
            STRUCT_FFI_STANDARD_is_rust_owned = ffiStandard.varHandle(MemoryLayout.PathElement.groupElement("is_rust_owned"));
        }

        public static void systemCallMemoryLock(boolean windows, final @NotNull MemorySegment target) {
            int result;
            try {
                if (windows) {
                    result = (int) wrapInvokeGlobal(OS_SC_VIRTUAL_LOCK, target, target.byteSize());
                    if (result == 0)
                        throw new ELIBSecurityCritical("""
                                Windows OS System Call -> VirtualLock 실패! 다음의 지침을 참고할 수 있습니다.
                                  - 프로세스의 작업 집합(Working Set) 제한을 확인하세요.
                                  - VirtualLock을 호출할 메모리 영역은 반드시 VirtualAlloc 등을 통해 MEM_COMMIT 상태로 커밋되어 있어야 합니다.
                                  - PAGE_NOACCESS로 보호된 메모리 영역은 잠글 수 없습니다. 읽기/쓰기 권한이 있어야 합니다.
                                  - VirtualLock은 페이지 단위로 작동합니다. 지정한 주소(lpAddress)와 크기(dwSize)가 페이지 경계에 걸쳐 있으면 관련 페이지가 모두 잠겨야 합니다.
                                  - 특수 권한(SE_LOCK_MEMORY_PRIVILEGE)이 필요할 수 있습니다.""");
                } else {
                    result = (int) wrapInvokeGlobal(OS_SC_MLOCK, target, target.byteSize());
                    if (result != 0)
                        throw new ELIBSecurityNativeCritical("""
                                Unix OS System Call -> mlock 실패! 다음의 지침을 참고할 수 있습니다.
                                  - RLIMIT_MEMLOCK (사용자별 잠금 가능 메모리 제한)을 초과했는지 확인하세요.
                                  - 시스템 전체 메모리가 부족하여 page를 잠그지 못할 수 있습니다.
                                  - 프로세스에 CAP_IPC_LOCK 기능이 없거나 루트(root) 권한이 아닐 수 있습니다.""");
                }
            } catch (ELIBSecurityProcessException e) {
                throw new ELIBSecurityNativeCritical("치명 오류");
            }
        }

        public static void systemCallMemoryUnlock(boolean windows, final @NotNull MemorySegment target) {
            int result;
            try {
                if (windows) {
                    result = (int) wrapInvokeGlobal(OS_SC_VIRTUAL_UNLOCK, target, target.byteSize());
                    if (result == 0)
                        throw new ELIBSecurityCritical(String.format("""
                                Windows OS System Call -> VirtualLock 실패! (code: %d) 다음의 지침을 따를 수 있습니다.
                                  - 해당 메모리 영역이 잠겨 있지 않은 상태일 수 있습니다.
                                  - lpAddress (시작 주소)와 dwSize (크기)가 유효한 메모리 범위를 가리키지 않을 수 있습니다.
                                  - VirtualUnlock은 해당 함수를 호출하는 프로세스의 작업 집합(Working Set)에 있는 메모리가 아닐 수 있습니다.
                                  - Windows 버전마다 프로세스가 잠글 수 있는 페이지 수에 제한이 있으며, 이 제한을 초과했을 수 있습니다.""", result));
                } else {
                    result = (int) wrapInvokeGlobal(OS_SC_MUNLOCK, target, target.byteSize());
                    if (result != 0)
                        throw new ELIBSecurityNativeCritical(String.format("""
                                Unix OS System Call -> mlock 실패! (code: %d) 다음의 지침을 따를 수 있습니다.
                                  - RLIMIT_MEMLOCK (사용자별 잠금 가능 메모리 제한)을 초과했는지 확인하세요.
                                  - 시스템 전체 메모리가 부족하여 page를 잠그지 못할 수 있습니다.
                                  - 프로세스에 CAP_IPC_LOCK 기능이 없거나 루트(root) 권한이 아닐 수 있습니다.""", result));
                }
            } catch (ELIBSecurityProcessException e) {
                throw new ELIBSecurityNativeCritical("치명 오류");
            }
        }

        public static NativeProcessResult<Void> joepOrder(final @NotNull MemorySegment target) throws ELIBSecurityProcessException {
            return wrapInvoke(FUNC_JOEP, null, target);
        }

        /// Rust FFI 통신을 위한 표준 규격 구조체를 안전하게 할당하고 초기화하는 메소드입니다.
        /// 직접적인 메모리 오프셋 접근을 차단하고 [VarHandle]을 통한 캡슐화된 주입을 보장합니다.
        ///
        /// @param arena       FFI 구조체가 할당될 단기 생명주기 제어 객체
        /// @param targetPtr   민감 데이터가 위치한 네이티브 메모리 포인터
        /// @param length      데이터의 실제 크기 (오버플로우 방지를 위해 `long` 타입 사용)
        /// @param isRustOwned 소유권 플래그
        /// @return 초기화가 완료된 FFIStandard 구조체의 메모리 세그먼트
        public static MemorySegment allocateFFIStandard(final @NotNull Arena arena,
                                                        final @NotNull MemorySegment targetPtr,
                                                        final long length,
                                                        final boolean isRustOwned) throws ELIBSecurityProcessException {
            try {
                // FFIStandard 구조체 레이아웃에 맞춰 안전하게 메모리 할당
                final MemorySegment ffiStruct = arena.allocate(
                        NativeComponent.STRUCT_FFI_STANDARD.getStructInfo().toStructLayout()
                );

                // 오프셋 휴먼 에러를 방지하기 위해 미리 초기화된 VarHandle을 통한 안전한 주입
                STRUCT_FFI_STANDARD_ptr.set(ffiStruct, 0L, targetPtr);
                STRUCT_FFI_STANDARD_len.set(ffiStruct, 0L, length);
                STRUCT_FFI_STANDARD_is_rust_owned.set(ffiStruct, 0L, isRustOwned);

                return ffiStruct;
            } catch (IllegalArgumentException | UnsupportedOperationException e) {
                throw new ELIBSecurityProcessException("FFIStandard 구조체 메모리 할당 및 초기화 중 치명적 오류가 발생했습니다. (레이아웃/타입 불일치)", e);
            }
        }

        /// [SensitiveDataContainer]를 기반으로 JO 패턴의 FFIStandard 구조체를 생성하는 헬퍼 메소드입니다.
        /// 비즈니스 로직에서 반복되는 보일러플레이트를 제거하고 소유권 정책을 강제합니다.
        public static MemorySegment allocateJOStandard(final @NotNull Arena arena,
                                                       final @NotNull SensitiveDataContainer sdc) throws ELIBSecurityProcessException {
            // UCA 대원칙에 따라 Java가 주도하여 생성한 데이터는 반드시 is_rust_owned = false
            // 패키지 내부 브릿지를 통해 내부 포인터에 안전하게 접근
            MemorySegment ptr = InternalNativeBridge.unwrapMemorySegment(sdc);
            return allocateFFIStandard(
                    arena,
                    ptr,
                    ptr.byteSize(),
                    false
            );
        }
    }

    public static final class Base64 {
        static final MethodHandle FUNC_BASE64_ENCODE;
        static final MethodHandle FUNC_BASE64_DECODE;

        static {
            FUNC_BASE64_ENCODE = withoutOSMethodHandles.get(NativeComponent.FUNC_BASE64_ENCODE);
            FUNC_BASE64_DECODE = withoutOSMethodHandles.get(NativeComponent.FUNC_BASE64_DECODE);
        }

        public static NativeProcessResult<Long> base64Encode(final @NotNull MemorySegment input, final @NotNull MemorySegment output)
                throws ELIBSecurityProcessException {
            return wrapInvoke(FUNC_BASE64_ENCODE, Long.class, input, output);
        }

        public static NativeProcessResult<Long> base64Decode(final @NotNull MemorySegment input, final @NotNull MemorySegment output)
                throws ELIBSecurityProcessException {
            return wrapInvoke(FUNC_BASE64_DECODE, Long.class, input, output);
        }
    }

    public static final class Hex {
        static final MethodHandle FUNC_HEX_ENCODE;
        static final MethodHandle FUNC_HEX_DECODE;

        static {
            FUNC_HEX_ENCODE = withoutOSMethodHandles.get(NativeComponent.FUNC_HEX_ENCODE);
            FUNC_HEX_DECODE = withoutOSMethodHandles.get(NativeComponent.FUNC_HEX_DECODE);
        }

        public static NativeProcessResult<Long> hexEncode(final @NotNull MemorySegment input, final @NotNull MemorySegment output)
                throws ELIBSecurityProcessException {
            return wrapInvoke(FUNC_HEX_ENCODE, Long.class, input, output);
        }

        public static NativeProcessResult<Long> hexDecode(final @NotNull MemorySegment input, final @NotNull MemorySegment output)
                throws ELIBSecurityProcessException {
            return wrapInvoke(FUNC_HEX_DECODE, Long.class, input, output);
        }
    }

    public static final class Hash {

        static NativeProcessResult<Long> hash(final @NotNull MethodHandle handle, final @NotNull MemorySegment input, final @NotNull MemorySegment output)
                throws ELIBSecurityProcessException {
            return wrapInvoke(handle, Long.class, input, output);
        }

        static NativeProcessResult<Long> hashBits(final @NotNull MethodHandle handle, final @NotNull MemorySegment input, final @NotNull MemorySegment output, final byte last, final long bits)
                throws ELIBSecurityProcessException {
            return wrapInvoke(handle, Long.class, input, output, last, bits);
        }

        public static final class SHA2 {
            static final MethodHandle FUNC_HASH_SHA2_224;
            static final MethodHandle FUNC_HASH_SHA2_256;
            static final MethodHandle FUNC_HASH_SHA2_384;
            static final MethodHandle FUNC_HASH_SHA2_512;

            static {
                FUNC_HASH_SHA2_224 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA2_224);
                FUNC_HASH_SHA2_256 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA2_256);
                FUNC_HASH_SHA2_384 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA2_384);
                FUNC_HASH_SHA2_512 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA2_512);
            }

            public static NativeProcessResult<Long> sha224(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA2_224, input, output);
            }

            public static NativeProcessResult<Long> sha256(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA2_256, input, output);
            }

            public static NativeProcessResult<Long> sha384(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA2_384, input, output);
            }

            public static NativeProcessResult<Long> sha512(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA2_512, input, output);
            }
        }

        public static final class SHA3 {
            static final MethodHandle FUNC_HASH_SHA3_224;
            static final MethodHandle FUNC_HASH_SHA3_256;
            static final MethodHandle FUNC_HASH_SHA3_384;
            static final MethodHandle FUNC_HASH_SHA3_512;
            static final MethodHandle FUNC_HASH_SHA3_224_BITS;
            static final MethodHandle FUNC_HASH_SHA3_256_BITS;
            static final MethodHandle FUNC_HASH_SHA3_384_BITS;
            static final MethodHandle FUNC_HASH_SHA3_512_BITS;

            static final MethodHandle FUNC_HASH_SHA3_SHAKE128;
            static final MethodHandle FUNC_HASH_SHA3_SHAKE256;
            static final MethodHandle FUNC_HASH_SHA3_SHAKE128_BITS;
            static final MethodHandle FUNC_HASH_SHA3_SHAKE256_BITS;

            static {
                FUNC_HASH_SHA3_224 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_224);
                FUNC_HASH_SHA3_256 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_256);
                FUNC_HASH_SHA3_384 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_384);
                FUNC_HASH_SHA3_512 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_512);
                FUNC_HASH_SHA3_224_BITS = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_224_BITS);
                FUNC_HASH_SHA3_256_BITS = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_256_BITS);
                FUNC_HASH_SHA3_384_BITS = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_384_BITS);
                FUNC_HASH_SHA3_512_BITS = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_512_BITS);

                FUNC_HASH_SHA3_SHAKE128 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_SHAKE128);
                FUNC_HASH_SHA3_SHAKE256 = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_SHAKE256);
                FUNC_HASH_SHA3_SHAKE128_BITS = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_SHAKE128_BITS);
                FUNC_HASH_SHA3_SHAKE256_BITS = withoutOSMethodHandles.get(NativeComponent.FUNC_HASH_SHA3_SHAKE256_BITS);
            }

            // pure
            public static NativeProcessResult<Long> sha224(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA3_224, input, output);
            }

            public static NativeProcessResult<Long> sha256(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA3_256, input, output);
            }

            public static NativeProcessResult<Long> sha384(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA3_384, input, output);
            }

            public static NativeProcessResult<Long> sha512(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA3_512, input, output);
            }

            public static NativeProcessResult<Long> shake128(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA3_SHAKE128, input, output);
            }

            public static NativeProcessResult<Long> shake256(final @NotNull MemorySegment input, final @NotNull MemorySegment output) throws ELIBSecurityProcessException {
                return hash(FUNC_HASH_SHA3_SHAKE256, input, output);
            }

            // bits
            public static NativeProcessResult<Long> sha224Bits(final @NotNull MemorySegment input, final @NotNull MemorySegment output, final byte last, final long valid) throws ELIBSecurityProcessException {
                return hashBits(FUNC_HASH_SHA3_224_BITS, input, output, last, valid);
            }

            public static NativeProcessResult<Long> sha256Bits(final @NotNull MemorySegment input, final @NotNull MemorySegment output, final byte last, final long valid) throws ELIBSecurityProcessException {
                return hashBits(FUNC_HASH_SHA3_256_BITS, input, output, last, valid);
            }

            public static NativeProcessResult<Long> sha384Bits(final @NotNull MemorySegment input, final @NotNull MemorySegment output, final byte last, final long valid) throws ELIBSecurityProcessException {
                return hashBits(FUNC_HASH_SHA3_384_BITS, input, output, last, valid);
            }

            public static NativeProcessResult<Long> sha512Bits(final @NotNull MemorySegment input, final @NotNull MemorySegment output, final byte last, final long valid) throws ELIBSecurityProcessException {
                return hashBits(FUNC_HASH_SHA3_512_BITS, input, output, last, valid);
            }

            public static NativeProcessResult<Long> shake128Bits(final @NotNull MemorySegment input, final @NotNull MemorySegment output, final byte last, final long valid) throws ELIBSecurityProcessException {
                return hashBits(FUNC_HASH_SHA3_SHAKE128_BITS, input, output, last, valid);
            }

            public static NativeProcessResult<Long> shake256Bits(final @NotNull MemorySegment input, final @NotNull MemorySegment output, final byte last, final long valid) throws ELIBSecurityProcessException {
                return hashBits(FUNC_HASH_SHA3_SHAKE256_BITS, input, output, last, valid);
            }
        }
    }
}