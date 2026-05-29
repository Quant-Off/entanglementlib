package space.qu4nt.entanglementlib.security.provider.entlibnative;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.ConstableFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeProcessResult;
import space.qu4nt.entanglementlib.security.provider.EncodingProvider;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/// `entlib-native` FFI 경계를 통해 Base64 / Hex 인/디코딩을 수행하는 [EncodingProvider] 구현입니다.
@ApiStatus.Internal
public final class EntLibNativeEncodingProvider implements EncodingProvider {

    @Override
    public SensitiveDataContainer base64Encode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        final long inputLen = InternalNativeBridge.unwrapMemorySegment(input).byteSize();
        if (inputLen > Long.MAX_VALUE / 2)
            throw new ELIBSecurityProcessException("Base64 인코딩 허용 메모리 한계를 초과했습니다!");
        // Base64 인코딩 시 필요한 정확한 버퍼 크기 계산 (패딩 포함)
        final int required = (int) (4 * ((inputLen + 2) / 3));
        final SensitiveDataContainer output = scope.allocate(required);

        try (Arena transientArena = Arena.ofConfined()) {
            final MemorySegment in = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            final MemorySegment out = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            final NativeProcessResult<Long> result = ConstableFactory.Base64.base64Encode(in, out);
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 Base64 인코딩 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (Throwable t) {
            if (t instanceof ELIBSecurityProcessException) throw (ELIBSecurityProcessException) t;
            throw new ELIBSecurityProcessException("Base64 인코딩 FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }

    @Override
    public SensitiveDataContainer base64Decode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        final long inputLen = InternalNativeBridge.unwrapMemorySegment(input).byteSize();
        // Base64 디코딩 시 필요한 최대 버퍼 크기 계산 (패딩 길이를 무시한 최대 보수값)
        final int maxRequired = (int) ((inputLen * 3) / 4);
        final SensitiveDataContainer output = scope.allocate(maxRequired);

        try (Arena transientArena = Arena.ofConfined()) {
            final MemorySegment in = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            final MemorySegment out = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            final NativeProcessResult<Long> result = ConstableFactory.Base64.base64Decode(in, out);
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 Base64 디코딩 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (Throwable t) {
            if (t instanceof ELIBSecurityProcessException) throw (ELIBSecurityProcessException) t;
            throw new ELIBSecurityProcessException("Base64 디코딩 FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }

    @Override
    public SensitiveDataContainer hexEncode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        final long inputLen = InternalNativeBridge.unwrapMemorySegment(input).byteSize();
        if (inputLen > Long.MAX_VALUE / 2)
            throw new ELIBSecurityProcessException("Hex 인코딩 허용 메모리 한계를 초과했습니다!");
        // Hex 인코딩 시 필요한 정확한 버퍼 크기 계산 (원본 * 2)
        final long required = inputLen * 2;
        final SensitiveDataContainer output = scope.allocate(required);

        try (Arena transientArena = Arena.ofConfined()) {
            final MemorySegment in = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            final MemorySegment out = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            final NativeProcessResult<Long> result = ConstableFactory.Hex.hexEncode(in, out);
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 Hex 인코딩 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (Throwable t) {
            if (t instanceof ELIBSecurityProcessException) throw (ELIBSecurityProcessException) t;
            throw new ELIBSecurityProcessException("Hex 인코딩 FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }

    @Override
    public SensitiveDataContainer hexDecode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        final long inputLen = InternalNativeBridge.unwrapMemorySegment(input).byteSize();

        // 홀수 길이를 즉각 거부하여 침묵적 절삭(Truncation) 방지
        if (inputLen % 2 != 0)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 Hex 인코딩 데이터입니다 (홀수 길이)!");

        // Hex 디코딩 시 필요한 정확한 버퍼 크기 계산 (원본 / 2)
        final long required = inputLen / 2;
        final SensitiveDataContainer output = scope.allocate(required);

        try (Arena transientArena = Arena.ofConfined()) {
            final MemorySegment in = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            final MemorySegment out = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            final NativeProcessResult<Long> result = ConstableFactory.Hex.hexDecode(in, out);
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 Hex 디코딩 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (Throwable t) {
            if (t instanceof ELIBSecurityProcessException) throw (ELIBSecurityProcessException) t;
            throw new ELIBSecurityProcessException("Hex 디코딩 FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }

    @Override
    public @NotNull String backendName() {
        return "entlib-native (FFI)";
    }
}
