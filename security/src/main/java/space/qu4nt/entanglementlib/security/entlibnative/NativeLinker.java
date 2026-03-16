package space.qu4nt.entanglementlib.security.entlibnative;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityNativeCritical;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.info.FunctionInfo;

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
public final class NativeLinker {

    private static final Linker linker = Linker.nativeLinker();
    private static final SymbolLookup osDefaultLookup;
    private static final SymbolLookup withoutOSLookup;

    // 동시성 문제 및 런타임 조작을 원천 차단하기 위한 불변 맵(Immutable Map)
    static Map<NativeComponent, MethodHandle> withoutOSMethodHandles;
    static Map<NativeComponent, MethodHandle> osDefaultMethodHandles;

    static {
        osDefaultLookup = linker.defaultLookup();
        withoutOSLookup = SymbolLookup.loaderLookup();
    }

    private NativeLinker() {
        throw new AssertionError("cannot access");
    }

    /// 이 메소드를 수행하여 정의된 함수 맵은 [ConstableFactory]에서 사용됨
    static synchronized void setup() {
        if (withoutOSMethodHandles != null) return; // 중복 호출 방지

        Map<NativeComponent, MethodHandle> withoutOSFunctionMap = new HashMap<>();
        Map<NativeComponent, MethodHandle> tempOSDefaultFunctionMap = new HashMap<>();
        for (NativeComponent nativeComponent : NativeComponent.LOADED) {
            if (nativeComponent.isStructComponent()) continue; // 구조체는 직접 핸들링
            if (nativeComponent.isOsDefault()) {
                tempOSDefaultFunctionMap.put(nativeComponent, downcall(true, nativeComponent));
                continue;
            }
            withoutOSFunctionMap.put(nativeComponent, downcall(false, nativeComponent));
        }

        // 맵을 불변 상태로 봉인
        withoutOSMethodHandles = Map.copyOf(withoutOSFunctionMap);
        osDefaultMethodHandles = Map.copyOf(tempOSDefaultFunctionMap);
    }

    private static MethodHandle downcall(boolean isOSDefault, final @NotNull NativeComponent nativeComponent) {
        final FunctionInfo functionInfo = nativeComponent.getFunctionInfo();
        final String functionName = functionInfo.getFunctionName();
        return linker.downcallHandle(isOSDefault ?
                osDefaultLookup.find(functionName).orElseThrow(() -> new ELIBSecurityNativeCritical("OS 기본 바이너리에서 함수 '" + functionName + "'을(를) 찾을 수 없습니다.")) :
                withoutOSLookup.find(functionName).orElseThrow(() -> new ELIBSecurityNativeCritical("네이티브에서 함수 '" + functionName + "'을(를) 찾을 수 없습니다.")),
                functionInfo.toFunctionDescriptor()
        );
    }

    @Deprecated
    public static MethodHandle call(final @NotNull NativeComponent nativeComponent) {
        MethodHandle handle = withoutOSMethodHandles.get(nativeComponent);
        if (handle == null)
            throw new ELIBSecurityNativeCritical("네이티브에서 함수 '" + nativeComponent.getFunctionInfo().getFunctionName() + "'이(가) 등록되지 않았습니다.");
        return handle;
    }

    public static @NotNull SensitiveDataContainer transferNativeBufferBindToContext(
            final @NotNull SDCScopeContext context,
            final @NotNull MemorySegment data
    ) throws ELIBSecurityProcessException {
        return null;
//        // Rust 측에서 메모리 해제가 완료되었는지 추적하여 Double-Free를 방지하기 위한 플래그
//        boolean isFreedByNative = false;
//
//        try {
//            long len = (long) MH_CALLEE_SECURE_BUFFER_LEN.invokeExact(data);
//
//            // Off-heap 메모리 할당 (OutOfMemoryError 등 예외 발생 가능 구간)
//            SensitiveDataContainer result = context.allocate((int) len);
//
//            // 네이티브에서 직접 복사 및 원본 즉시 소거 (단 1회의 FFI 호출로 압축)
//            long copied = (long) MH_CALLEE_SECURE_BUFFER_COPY_AND_FREE.invokeExact(
//                    data,
//                    InternalNativeBridge.unwrapMemorySegment(result),
//                    len
//            );
//
//            // invokeExact가 예외 없이 통과했다면 Rust의 Box::from_raw에 의해 무조건 소멸
//            isFreedByNative = true;
//
//            // 용량 불일치 등 논리적 오류 검증
//            if (copied != len)
//                throw new ELIBSecurityCritical("네이티브 버퍼 복사 중 크기 불일치 또는 오류가 발생했습니다.");
//
//            return result;
//        } catch (Throwable e) {
//            // context.allocate() 실패 등 Rust로 제어권이 넘어가기 전에 예외가 발생한 경우 메모리 누수 방지
//            if (!isFreedByNative) {
//                try {
//                    MH_CALLEE_SECURE_BUFFER_FREE.invokeExact(data);
//                } catch (Throwable ex) {
//                    // 원본 예외 유실을 막기 위해 억제된 예외로 병합
//                    e.addSuppressed(ex);
//                    throw new ELIBSecurityCritical("네이티브 데이터를 소거하는 중 치명적 오류가 발생했습니다!", e);
//                }
//            }
//
//            // 이미 Critical 예외인 경우 그대로 던짐
//            if (e instanceof ELIBSecurityCritical) throw (ELIBSecurityCritical) e;
//            throw new ELIBSecurityProcessException("네이티브 버퍼 획득 및 전송 중 예외가 발생했습니다!", e);
//        }
    }
}