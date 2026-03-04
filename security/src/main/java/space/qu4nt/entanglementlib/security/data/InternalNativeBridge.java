package space.qu4nt.entanglementlib.security.data;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.annotations.Unsafe;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Objects;

public final class InternalNativeBridge {

    private InternalNativeBridge() {
    }

    @Unsafe("사용자가 직접 Arena를 조작하는 것은 권장되지 않음")
    public static @NotNull Arena unwrapArena(final @NotNull SensitiveDataContainer container) {
        return Objects.requireNonNull(container, "container").getArena();
    }

    @Unsafe("MemorySegment는 내부적으로 heap에 데이터가 운반될 수 있는 기능을 포함")
    public static @NotNull MemorySegment unwrapMemorySegment(final @NotNull SensitiveDataContainer container) {
        return Objects.requireNonNull(container, "container").getMemorySegment();
    }
}
