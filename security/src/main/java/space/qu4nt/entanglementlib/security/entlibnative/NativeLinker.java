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

    /// Rust-Owned(RO) 패턴 전송 메소드입니다. Rust가 할당한 SecureBuffer 포인터의 내용을
    /// Java가 관리하는 [SensitiveDataContainer]로 복사하고 원본 네이티브 버퍼를 즉시 소거합니다.
    ///
    /// # Status
    /// 이 경로는 네이티브 측 callee secure-buffer 함수(`secure_buffer_len`,
    /// `secure_buffer_copy_and_free`, `secure_buffer_free`)에 의존하지만 현재 `entlib-native`
    /// FFI에 노출되지 않았습니다. 현재 모든 보안 연산(base64/hex/SHA-2/SHA-3)은 Java-Owned(JO)
    /// 원샷 패턴으로, 출력 버퍼를 Java가 사전 할당하여 전달하므로 이 RO 경로가 필요하지 않습니다.
    ///
    /// 해당 callee 함수가 노출되면 단일 FFI 호출(copy-and-free)로 복사 및 원본 소거를 수행하도록
    /// 구현합니다.
    ///
    /// @throws ELIBSecurityProcessException callee secure-buffer FFI 미노출로 항상 발생
    public static @NotNull SensitiveDataContainer transferNativeBufferBindToContext(
            final @NotNull SDCScopeContext context,
            final @NotNull MemorySegment data
    ) throws ELIBSecurityProcessException {
        throw new ELIBSecurityProcessException(
                "RO(Rust-Owned) 전송 경로는 아직 entlib-native FFI에 노출되지 않았습니다. " +
                "현재는 JO(Java-Owned) 원샷 패턴만 지원됩니다.");
    }
}