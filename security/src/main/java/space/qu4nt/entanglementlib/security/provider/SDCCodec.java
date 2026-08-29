package space.qu4nt.entanglementlib.security.provider;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;

/// heap 기반 검증 공급자(JDK JCA, BouncyCastle FIPS 등)가 off-heap [SensitiveDataContainer]와
/// 라이브러리가 요구하는 `byte[]` 사이를 잇기 위한 내부 브리지 헬퍼입니다.
///
/// # Security Note
/// JCA(MessageDigest, Cipher 등)와 BouncyCastle 경량 API는 `byte[]`로만 동작하므로 검증 백엔드를
/// 선택하면 연산 시간 동안 민감 데이터가 JVM `heap`에 잠시 노출됩니다. 이는 README가 명시한 의도된
/// 절충(검증된 정확성을 위해 짧은 heap 노출을 감수)입니다. 이 헬퍼는 사용한 모든 임시 `byte[]`를
/// [#wipe]로 즉시 0으로 덮어 잔류 시간을 최소화합니다.
@ApiStatus.Internal
public final class SDCCodec {

    private SDCCodec() {
        throw new AssertionError("cannot access");
    }

    /// 컨테이너의 off-heap 바이트를 `heap` 배열로 복사합니다. 호출자는 사용 후 [#wipe]로 소거해야 합니다.
    public static byte @NotNull [] read(final @NotNull SensitiveDataContainer container) {
        return InternalNativeBridge.unwrapMemorySegment(container).toArray(ValueLayout.JAVA_BYTE);
    }

    /// `heap` 배열의 내용을 스코프에 새로 할당한 off-heap 컨테이너로 복사하여 반환합니다.
    /// 원본 `data`는 이 메소드 내부에서 소거하지 않습니다. 호출자가 [#wipe]로 소거해야 합니다.
    public static @NotNull SensitiveDataContainer write(final @NotNull SDCScopeContext scope, final byte @NotNull [] data)
            throws ELIBSecurityProcessException {
        final SensitiveDataContainer output = scope.allocate(data.length);
        if (data.length > 0) {
            final MemorySegment dst = InternalNativeBridge.unwrapMemorySegment(output);
            MemorySegment.copy(data, 0, dst, ValueLayout.JAVA_BYTE, 0, data.length);
        }
        return output;
    }

    /// 전달된 모든 `byte[]`를 0으로 덮어 `heap` 잔류 데이터를 소거합니다. `null`은 무시합니다.
    public static void wipe(final byte[]... arrays) {
        for (byte[] array : arrays) {
            if (array != null)
                Arrays.fill(array, (byte) 0);
        }
    }
}
