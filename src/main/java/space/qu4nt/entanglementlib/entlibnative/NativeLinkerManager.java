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
import java.util.ArrayList;
import java.util.List;
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

    private static final String OS_NAME = System.getProperty("os.name").toLowerCase();
    private static final String OS_ARCH = System.getProperty("os.arch").toLowerCase();

    private final SymbolLookup lookup;
    private final Linker linker;

    private String libName;
    private Map<String, MethodHandle> handles;

    public NativeLinkerManager(final @NotNull String libName) {
        Objects.requireNonNull(libName);
        Path nativeDir = Path.of(InternalFactory.envEntLibNativeDir()).toAbsolutePath();
        Path lib = resolveNativeLibrary(nativeDir, libName);
        if (lib == null)
            throw new EntLibNativeError("네이티브 라이브러리 '" + libName + "'을(를) 찾을 수 없습니다! " +
                    "(검색 경로: " + nativeDir + ", OS: " + OS_NAME + ", Arch: " + OS_ARCH + ")");
        this.libName = lib.getFileName().toString();
        log.debug("네이티브 라이브러리 로드: {}", lib);
        this.lookup = SymbolLookup.libraryLookup(lib, Arena.global());
        this.linker = Linker.nativeLinker();
        this.handles = new ConcurrentHashMap<>();
    }

    /// 현재 플랫폼과 아키텍처에 맞는 네이티브 라이브러리 파일을 찾는 메소드입니다.
    /// 검색 우선순위는 다음과 같습니다.
    ///
    /// 1. 정확한 이름 (예: libentlib_native.dylib)
    /// 2. 아키텍처 특정 이름 (예: libentlib_native_aarch64.dylib)
    /// 3. macOS의 경우 universal 바이너리 (예: libentlib_native_universal.dylib)
    ///
    /// @param nativeDir 바이너리 파일이 위치한 네이티브 디렉토리
    /// @param libName   네이티브 라이브러리명
    /// @return 특정된 바이너리 파일
    private static Path resolveNativeLibrary(@NotNull Path nativeDir, @NotNull String libName) {
        List<String> candidates = generateCandidateNames(libName);
        for (String candidate : candidates) {
            Path path = nativeDir.resolve(candidate);
            if (Files.exists(path)) {
                return path;
            }
        }
        return null;
    }

    /// 플랫폼과 아키텍처에 따라 후보 파일명 목록을 생성하는 메소드입니다.
    private static List<String> generateCandidateNames(@NotNull String libName) {
        List<String> candidates = new ArrayList<>();
        String archSuffix = getArchitectureSuffix();
        String ext = getLibraryExtension();
        String prefix = getLibraryPrefix();

        // 1. 정확한 이름 (System.mapLibraryName과 동일)
        candidates.add(prefix + libName + ext);

        // 2. 아키텍처 특정 이름
        candidates.add(prefix + libName + "_" + archSuffix + ext);

        // 3. macOS의 경우 universal 바이너리
        if (isMacOS()) {
            candidates.add(prefix + libName + "_universal" + ext);
        }

        return candidates;
    }

    private static String getArchitectureSuffix() {
        if (OS_ARCH.contains("aarch64") || OS_ARCH.contains("arm64")) {
            return "aarch64";
        } else if (OS_ARCH.contains("amd64") || OS_ARCH.contains("x86_64")) {
            return "x86_64";
        } else if (OS_ARCH.contains("x86") || OS_ARCH.contains("i386") || OS_ARCH.contains("i686")) {
            return "i686";
        }
        return OS_ARCH;
    }

    private static String getLibraryExtension() {
        if (isMacOS()) return ".dylib";
        if (isWindows()) return ".dll";
        return ".so";
    }

    private static String getLibraryPrefix() {
        if (isWindows()) return "";
        return "lib";
    }

    private static boolean isMacOS() {
        return OS_NAME.contains("mac") || OS_NAME.contains("darwin");
    }

    private static boolean isWindows() {
        return OS_NAME.contains("win");
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
