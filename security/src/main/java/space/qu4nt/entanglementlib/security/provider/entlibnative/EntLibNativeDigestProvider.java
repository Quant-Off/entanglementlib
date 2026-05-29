package space.qu4nt.entanglementlib.security.provider.entlibnative;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.ConstableFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeProcessResult;
import space.qu4nt.entanglementlib.security.provider.DigestProvider;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/// `entlib-native` FFI 경계를 통해 다이제스트 연산을 수행하는 [DigestProvider] 구현입니다.
///
/// # Note
/// 이 백엔드는 암호학적 검증이 충분히 이루어지지 않은 시험적 구현입니다. 검증된 연산이 필요하면
/// JDK 검증 공급자 또는 사용자 정의 공급자를 사용하세요.
@ApiStatus.Internal
public final class EntLibNativeDigestProvider implements DigestProvider {

    @Override
    public SensitiveDataContainer sha2(final @NotNull SDCScopeContext scope, final int length, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        final int digestBytes = digestByteSize(length);
        final SensitiveDataContainer output = scope.allocate(digestBytes);
        try (Arena transientArena = Arena.ofConfined()) {
            final MemorySegment in = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            final MemorySegment out = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            final NativeProcessResult<Long> result = switch (length) {
                case 224 -> ConstableFactory.Hash.SHA2.sha224(in, out);
                case 256 -> ConstableFactory.Hash.SHA2.sha256(in, out);
                case 384 -> ConstableFactory.Hash.SHA2.sha384(in, out);
                case 512 -> ConstableFactory.Hash.SHA2.sha512(in, out);
                default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHA-2 길이입니다: " + length);
            };
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 SHA-2 연산 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("SHA-2 FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }

    @Override
    public SensitiveDataContainer sha3(final @NotNull SDCScopeContext scope, final int length, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        final int digestBytes = digestByteSize(length);
        final SensitiveDataContainer output = scope.allocate(digestBytes);
        try (Arena transientArena = Arena.ofConfined()) {
            final MemorySegment in = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            final MemorySegment out = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            final NativeProcessResult<Long> result = switch (length) {
                case 224 -> ConstableFactory.Hash.SHA3.sha224(in, out);
                case 256 -> ConstableFactory.Hash.SHA3.sha256(in, out);
                case 384 -> ConstableFactory.Hash.SHA3.sha384(in, out);
                case 512 -> ConstableFactory.Hash.SHA3.sha512(in, out);
                default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHA-3 길이입니다: " + length);
            };
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 SHA-3 연산 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("SHA-3 FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }

    @Override
    public SensitiveDataContainer shake(final @NotNull SDCScopeContext scope, final int variant, final long outputBytes, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        if (variant != 128 && variant != 256)
            throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHAKE 변형입니다: " + variant);
        if (outputBytes <= 0 || outputBytes > Integer.MAX_VALUE)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 SHAKE 출력 길이입니다: " + outputBytes);

        final SensitiveDataContainer output = scope.allocate((int) outputBytes);
        try (Arena transientArena = Arena.ofConfined()) {
            final MemorySegment in = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            final MemorySegment out = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            final NativeProcessResult<Long> result = switch (variant) {
                case 128 -> ConstableFactory.Hash.SHA3.shake128(in, out);
                case 256 -> ConstableFactory.Hash.SHA3.shake256(in, out);
                default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHAKE 변형입니다: " + variant);
            };
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 SHAKE 연산 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("SHAKE FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }

    @Override
    public @NotNull String backendName() {
        return "entlib-native (FFI)";
    }

    private static int digestByteSize(final int length) throws ELIBSecurityProcessException {
        return switch (length) {
            case 224 -> 28;
            case 256 -> 32;
            case 384 -> 48;
            case 512 -> 64;
            default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 다이제스트 길이입니다: " + length);
        };
    }
}
