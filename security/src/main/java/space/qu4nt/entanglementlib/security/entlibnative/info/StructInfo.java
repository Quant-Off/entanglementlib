package space.qu4nt.entanglementlib.security.entlibnative.info;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.StructLayout;
import java.lang.invoke.VarHandle;
import java.util.LinkedHashMap;
import java.util.Map;

public class StructInfo {

    private @NotNull String structName;
    /// 구조체 필드의 선언 순서가 곧 메모리 레이아웃 순서이므로 삽입 순서를 보존하는 맵을 사용
    private final Map<String, MemoryLayout> params;

    private StructInfo(@NotNull String structName, Map<String, MemoryLayout> params) {
        this.structName = structName;
        this.params = params;
    }

    public static StructInfo of(final @NotNull String structName, final @NotNull String paramName, final @NotNull MemoryLayout paramType) {
        final Map<String, MemoryLayout> params = new LinkedHashMap<>();
        params.put(paramName, paramType);
        return new StructInfo(structName, params);
    }

    public static StructInfo of(final @NotNull String structName,
                                final @NotNull String paramName1, final @NotNull MemoryLayout paramType1,
                                final @NotNull String paramName2, final @NotNull MemoryLayout paramType2) {
        final Map<String, MemoryLayout> params = new LinkedHashMap<>();
        params.put(paramName1, paramType1);
        params.put(paramName2, paramType2);
        return new StructInfo(structName, params);
    }

    public static StructInfo of(final @NotNull String structName,
                                final @NotNull String paramName1, final @NotNull MemoryLayout paramType1,
                                final @NotNull String paramName2, final @NotNull MemoryLayout paramType2,
                                final @NotNull String paramName3, final @NotNull MemoryLayout paramType3) {
        final Map<String, MemoryLayout> params = new LinkedHashMap<>();
        params.put(paramName1, paramType1);
        params.put(paramName2, paramType2);
        params.put(paramName3, paramType3);
        return new StructInfo(structName, params);
    }

    public static StructInfo of(@NotNull String structName,
                                final @NotNull String paramName1, final @NotNull MemoryLayout paramType1,
                                final @NotNull String paramName2, final @NotNull MemoryLayout paramType2,
                                final @NotNull String paramName3, final @NotNull MemoryLayout paramType3,
                                final @NotNull String paramName4, final @NotNull MemoryLayout paramType4) {
        final Map<String, MemoryLayout> params = new LinkedHashMap<>();
        params.put(paramName1, paramType1);
        params.put(paramName2, paramType2);
        params.put(paramName3, paramType3);
        params.put(paramName4, paramType4);
        return new StructInfo(structName, params);
    }

    public @Nullable MemoryLayout getParameterLayout(final @NotNull String paramName) {
        return params.get(paramName);
    }

    public StructLayout toStructLayout() {
        return MemoryLayout.structLayout(
                params.entrySet().stream()
                        .map(e -> {
                            final String key = e.getKey();
                            if (key.equals("_PADDING")) return e.getValue();
                            return e.getValue().withName(e.getKey());
                        })
                        .toArray(MemoryLayout[]::new)
        ).withName(structName);
    }

    public VarHandle accessField(final @NotNull String paramName) {
        return toStructLayout().varHandle(MemoryLayout.PathElement.groupElement(paramName));
    }

    public @NotNull String getStructName() {
        return structName;
    }

    public void setStructName(@NotNull String structName) {
        this.structName = structName;
    }
}
