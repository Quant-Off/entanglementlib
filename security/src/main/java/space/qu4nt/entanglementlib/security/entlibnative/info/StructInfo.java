package space.qu4nt.entanglementlib.security.entlibnative.info;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.lang.constant.Constable;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.StructLayout;
import java.lang.invoke.VarHandle;
import java.util.Map;

public class StructInfo {

    @Getter
    @Setter
    private @NotNull String structName;
    private final Map<String, MemoryLayout> params;

    private StructInfo(@NotNull String structName, Map<String, MemoryLayout> params) {
        this.structName = structName;
        this.params = params;
    }

    public static StructInfo of(final @NotNull String structName, final @NotNull String paramName, final @NotNull MemoryLayout paramType) {
        return new StructInfo(structName, Map.of(paramName, paramType));
    }

    public static StructInfo of(final @NotNull String structName,
                                final @NotNull String paramName1, final @NotNull MemoryLayout paramType1,
                                final @NotNull String paramName2, final @NotNull MemoryLayout paramType2) {
        return new StructInfo(structName, Map.of(paramName1, paramType1, paramName2, paramType2));
    }

    public static StructInfo of(final @NotNull String structName,
                                final @NotNull String paramName1, final @NotNull MemoryLayout paramType1,
                                final @NotNull String paramName2, final @NotNull MemoryLayout paramType2,
                                final @NotNull String paramName3, final @NotNull MemoryLayout paramType3) {
        return new StructInfo(structName, Map.of(paramName1, paramType1, paramName2, paramType2, paramName3, paramType3));
    }

    public static StructInfo of(@NotNull String structName,
                                final @NotNull String paramName1, final @NotNull MemoryLayout paramType1,
                                final @NotNull String paramName2, final @NotNull MemoryLayout paramType2,
                                final @NotNull String paramName3, final @NotNull MemoryLayout paramType3,
                                final @NotNull String paramName4, final @NotNull MemoryLayout paramType4) {
        return new StructInfo(structName, Map.of(paramName1, paramType1, paramName2, paramType2, paramName3, paramType3, paramName4, paramType4));
    }

    public @Nullable MemoryLayout getParameterLayout(final @NotNull String paramName) {
        if (params.containsKey(paramName))
            return params.get(paramName);
        return null;
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
}
