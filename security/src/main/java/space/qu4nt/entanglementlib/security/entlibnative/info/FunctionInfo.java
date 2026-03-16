package space.qu4nt.entanglementlib.security.entlibnative.info;

import lombok.Getter;
import lombok.Setter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.lang.constant.Constable;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryLayout;
import java.util.List;

public class FunctionInfo {

    @Getter
    @Setter
    private String functionName;
    private @Nullable MemoryLayout returnType;
    private List<@NotNull MemoryLayout> argLayouts;

    private FunctionInfo(String functionName, @Nullable MemoryLayout returnType, List<MemoryLayout> argLayouts) {
        this.functionName = functionName;
        this.returnType = returnType;
        this.argLayouts = argLayouts;
    }

    public static FunctionInfo of(final String functionName, @NotNull FunctionInfo ref) {
        return new FunctionInfo(functionName, ref.returnType, ref.argLayouts);
    }

    public static FunctionInfo ofVoid(final String functionName, @NotNull FunctionInfo ref) {
        return new FunctionInfo(functionName, null, ref.argLayouts);
    }

    public static FunctionInfo of(final String functionName, @NotNull MemoryLayout returnType, MemoryLayout... args) {
        return new FunctionInfo(functionName, returnType, calibration(args));
    }

    public static FunctionInfo ofVoid(final @NotNull String functionName, MemoryLayout... args) {
        return new FunctionInfo(functionName, null, calibration(args));
    }

    public FunctionInfo andArg(final @NotNull MemoryLayout additional) {
        this.argLayouts.add(additional);
        return this;
    }

    public FunctionDescriptor toFunctionDescriptor() {
        if (returnType == null)
            return FunctionDescriptor.ofVoid(argLayouts.toArray(MemoryLayout[]::new));
        return FunctionDescriptor.of(returnType, argLayouts.toArray(MemoryLayout[]::new));
    }

    private static List<MemoryLayout> calibration(MemoryLayout[] args) {
        return args.length == 0 ? null : List.of(args);
    }
}
