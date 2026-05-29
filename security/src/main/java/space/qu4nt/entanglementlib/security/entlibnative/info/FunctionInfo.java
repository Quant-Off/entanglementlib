package space.qu4nt.entanglementlib.security.entlibnative.info;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryLayout;
import java.util.ArrayList;
import java.util.List;

public class FunctionInfo {

    private String functionName;
    private @Nullable MemoryLayout returnType;
    private List<@NotNull MemoryLayout> argLayouts;

    private FunctionInfo(String functionName, @Nullable MemoryLayout returnType, List<MemoryLayout> argLayouts) {
        this.functionName = functionName;
        this.returnType = returnType;
        this.argLayouts = argLayouts;
    }

    public static FunctionInfo of(final String functionName, @NotNull FunctionInfo ref) {
        // ref의 인자 레이아웃을 가변 리스트로 복사하여 andArg 변형이 ref를 오염시키지 않도록 함
        return new FunctionInfo(functionName, ref.returnType, copyOf(ref.argLayouts));
    }

    public static FunctionInfo ofVoid(final String functionName, @NotNull FunctionInfo ref) {
        return new FunctionInfo(functionName, null, copyOf(ref.argLayouts));
    }

    public static FunctionInfo of(final String functionName, @NotNull MemoryLayout returnType, MemoryLayout... args) {
        return new FunctionInfo(functionName, returnType, calibration(args));
    }

    public static FunctionInfo ofVoid(final @NotNull String functionName, MemoryLayout... args) {
        return new FunctionInfo(functionName, null, calibration(args));
    }

    public FunctionInfo andArg(final @NotNull MemoryLayout additional) {
        if (this.argLayouts == null)
            this.argLayouts = new ArrayList<>();
        this.argLayouts.add(additional);
        return this;
    }

    public FunctionDescriptor toFunctionDescriptor() {
        final MemoryLayout[] args = argLayouts == null
                ? new MemoryLayout[0]
                : argLayouts.toArray(MemoryLayout[]::new);
        if (returnType == null)
            return FunctionDescriptor.ofVoid(args);
        return FunctionDescriptor.of(returnType, args);
    }

    public String getFunctionName() {
        return functionName;
    }

    public void setFunctionName(String functionName) {
        this.functionName = functionName;
    }

    private static List<MemoryLayout> calibration(MemoryLayout[] args) {
        return args.length == 0 ? new ArrayList<>() : new ArrayList<>(List.of(args));
    }

    private static List<MemoryLayout> copyOf(@Nullable List<MemoryLayout> source) {
        return source == null ? new ArrayList<>() : new ArrayList<>(source);
    }
}
