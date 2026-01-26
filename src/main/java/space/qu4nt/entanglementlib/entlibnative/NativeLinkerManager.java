/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.entlibnative;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.critical.EntLibNativeError;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/// 얽힘 라이브러리 네이티브 라이브러리 브릿지를 위한 매니지먼트 클래스입니다.
/// 해당 클래스는 [InternalFactory]를 통해 런타임에서 생성 후 변경되지
/// 않습니다. 따라서 호출은 [#NativeLinkerManager(String)]가 아닌
/// [InternalFactory#callNativeLib()] 메소드를 사용해야 합니다.
///
/// 이 클래스를 외부에서 사용한다면 사용자 설정된 네이티브를 호출할 수도
/// 있지만, 이 클래스는 기본적으로 얽힘 라이브러리에서 `entlib-native`
/// 라이브러리만이 호출됨을 예상합니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
@Slf4j
@Getter
@Setter
public class NativeLinkerManager {

    private final SymbolLookup lookup;
    private final Linker linker;

    private String libName;
    private Map<String, MethodHandle> handles;

    public NativeLinkerManager(final @NotNull String libName) {
        this.libName = System.mapLibraryName(Objects.requireNonNull(libName));
        Path lib = Path.of(InternalFactory.envEntLibNativeDir(), this.libName).toAbsolutePath();
        if (Files.notExists(lib))
            throw new EntLibNativeError("네이티브 라이브러리 '" + libName + "'을(를) 찾을 수 없습니다!");
        this.lookup = SymbolLookup.libraryLookup(lib, Arena.global());
        this.linker = Linker.nativeLinker();
        this.handles = new ConcurrentHashMap<>();
    }

    @NotNull
    public FunctionDescriptor descriptor(@NotNull MemoryLayout resLayout, MemoryLayout... argLayouts) {
        return FunctionDescriptor.of(resLayout, argLayouts);
    }

    @NotNull
    public FunctionDescriptor descriptorVoid(MemoryLayout... argLayouts) {
        return FunctionDescriptor.ofVoid(argLayouts);
    }

    @NotNull
    MethodHandle getLookup(@NotNull String name, FunctionDescriptor function) {
        return lookup.find(name)
                .map(symbol -> linker.downcallHandle(symbol, function))
                .orElseThrow(() -> new EntLibNativeError("네이티브 함수 '" + name + "'을(를) 찾을 수 없습니다!"));
    }

    /// static 블럭에서 사용해야함
    public NativeLinkerManager addVoidMethodHandle(@NotNull String name, MemoryLayout... argLayouts) {
        handles.put(name, getLookup(name, descriptorVoid(argLayouts)));
        log.debug("\t네이티브 함수 '{}'을(를) 연결했습니다.", name);
        return this;
    }

    /// static 블럭에서 사용해야함
    public NativeLinkerManager addReturnableMethodHandle(@NotNull String name, @NotNull MemoryLayout resLayout, MemoryLayout... argLayouts) {
        handles.put(name, getLookup(name, descriptor(resLayout, argLayouts)));
        log.debug("\t반환값을 가진 네이티브 함수 '{}'을(를) 연결했습니다.", name);
        return this;
    }

    @NotNull
    public MethodHandle getHandle(final @NotNull String name) {
        MethodHandle handle = handles.getOrDefault(name, null);
        if (handle == null)
            throw new EntLibNativeError("네이티브 함수 '" + name + "'을(를) 찾을 수 없습니다!");
        return handle;
    }
}
