package space.qu4nt.entanglementlib.security.entlibnative;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityCritical;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityNativeCritical;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.util.HashMap;
import java.util.Map;

/// 해당 클래스를 통해 네이티브 함수를 호출하는 경우, 반드시 [NativeLoader]에 의해
/// 타겟 네이티브 라이브러리가 시스템에 등록(선행)되어 있어야 합니다.
///
/// @author Q. T. Felix
/// @since 1.1.1
public final class EntLibNativeManager {

    private static final SymbolLookup lookup;
    private static final Linker linker = Linker.nativeLinker();

    // 동시성 문제 및 런타임 조작을 원천 차단하기 위한 불변 맵(Immutable Map)
    private static Map<Function, MethodHandle> methodHandles;

    // 핫 패스(Hot Path) 최적화를 위한 핵심 MethodHandle 정적 캐시
    @SuppressWarnings({"FieldCanBeLocal", "unused"})
    private static MethodHandle MH_CALLEE_SECURE_BUFFER_DATA;
    private static MethodHandle MH_CALLEE_SECURE_BUFFER_LEN;
    private static MethodHandle MH_CALLEE_SECURE_BUFFER_FREE;
    private static MethodHandle MH_CALLEE_SECURE_BUFFER_COPY_AND_FREE;

    static {
        lookup = SymbolLookup.loaderLookup();
    }

    private EntLibNativeManager() {
        throw new AssertionError("cannot access");
    }

    static synchronized void setup() {
        if (methodHandles != null) return; // 중복 호출 방지

        Map<Function, MethodHandle> tempMap = new HashMap<>();
        for (Function function : Function.LOADED)
            tempMap.put(function, linkExact(function));

        // 맵을 불변 상태로 봉인
        methodHandles = Map.copyOf(tempMap);

        // 핵심 기능은 O(1)의 Map 탐색 비용조차 없애기 위해 정적 필드에 다이렉트 바인딩
        MH_CALLEE_SECURE_BUFFER_DATA = methodHandles.get(Function.Callee_Secure_Buffer_Data);
        MH_CALLEE_SECURE_BUFFER_LEN = methodHandles.get(Function.Callee_Secure_Buffer_Len);
        MH_CALLEE_SECURE_BUFFER_FREE = methodHandles.get(Function.Callee_Secure_Buffer_Free);
        MH_CALLEE_SECURE_BUFFER_COPY_AND_FREE = methodHandles.get(Function.SecureBuffer_CopyAndFree);
    }

    private static MethodHandle linkExact(final @NotNull Function function) {
        return linker.downcallHandle(
                lookup.find(function.getFunctionName()).orElseThrow(() ->
                        new ELIBSecurityNativeCritical("네이티브에서 함수 '" + function.getFunctionName() + "'을(를) 찾을 수 없습니다.")),
                function.getDescriptor()
        );
    }

    public static MethodHandle call(final @NotNull Function function) {
        MethodHandle handle = methodHandles.get(function);
        if (handle == null)
            throw new ELIBSecurityNativeCritical("네이티브에서 함수 '" + function.getFunctionName() + "'이(가) 등록되지 않았습니다.");
        return handle;
    }

    public static @NotNull SensitiveDataContainer transferNativeBufferBindToContext(
            final @NotNull SDCScopeContext context,
            final @NotNull MemorySegment data
    ) throws ELIBSecurityProcessException {
        // Rust 측에서 메모리 해제가 완료되었는지 추적하여 Double-Free를 방지하기 위한 플래그
        boolean isFreedByNative = false;

        try {
            long len = (long) MH_CALLEE_SECURE_BUFFER_LEN.invokeExact(data);

            // Off-heap 메모리 할당 (OutOfMemoryError 등 예외 발생 가능 구간)
            SensitiveDataContainer result = context.allocate((int) len);

            // 네이티브에서 직접 복사 및 원본 즉시 소거 (단 1회의 FFI 호출로 압축)
            long copied = (long) MH_CALLEE_SECURE_BUFFER_COPY_AND_FREE.invokeExact(
                    data,
                    InternalNativeBridge.unwrapMemorySegment(result),
                    len
            );

            // invokeExact가 예외 없이 통과했다면 Rust의 Box::from_raw에 의해 무조건 소멸
            isFreedByNative = true;

            // 용량 불일치 등 논리적 오류 검증
            if (copied != len)
                throw new ELIBSecurityCritical("네이티브 버퍼 복사 중 크기 불일치 또는 오류가 발생했습니다.");

            return result;
        } catch (Throwable e) {
            // context.allocate() 실패 등 Rust로 제어권이 넘어가기 전에 예외가 발생한 경우 메모리 누수 방지
            if (!isFreedByNative) {
                try {
                    MH_CALLEE_SECURE_BUFFER_FREE.invokeExact(data);
                } catch (Throwable ex) {
                    // 원본 예외 유실을 막기 위해 억제된 예외로 병합
                    e.addSuppressed(ex);
                    throw new ELIBSecurityCritical("네이티브 데이터를 소거하는 중 치명적 오류가 발생했습니다!", e);
                }
            }

            // 이미 Critical 예외인 경우 그대로 던짐
            if (e instanceof ELIBSecurityCritical) throw (ELIBSecurityCritical) e;
            throw new ELIBSecurityProcessException("네이티브 버퍼 획득 및 전송 중 예외가 발생했습니다!", e);
        }
    }
}