package space.qu4nt.entanglementlib.security.entlibnative;

import lombok.Getter;
import lombok.Setter;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.lang.foreign.MemorySegment;
import java.util.Objects;

@Getter
@Setter
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
}
