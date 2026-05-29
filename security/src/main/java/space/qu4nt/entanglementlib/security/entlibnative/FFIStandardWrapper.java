package space.qu4nt.entanglementlib.security.entlibnative;

import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.lang.foreign.MemorySegment;
import java.util.Objects;

public class FFIStandardWrapper {
    private MemorySegment target;
    private long length;

    private FFIStandardWrapper(MemorySegment target) {
        this.target = target;
        this.length = target.byteSize();
    }

    public static FFIStandardWrapper createFFIStruct(final SensitiveDataContainer sdc) {
        return new FFIStandardWrapper(InternalNativeBridge.unwrapMemorySegment(Objects.requireNonNull(sdc, "SDC")));
    }

    public MemorySegment getTarget() {
        return target;
    }

    public void setTarget(MemorySegment target) {
        this.target = target;
    }

    public long getLength() {
        return length;
    }

    public void setLength(long length) {
        this.length = length;
    }
}
