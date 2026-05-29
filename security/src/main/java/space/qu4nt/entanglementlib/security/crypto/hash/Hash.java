package space.qu4nt.entanglementlib.security.crypto.hash;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.ConstableFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeProcessResult;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/// 네이티브 메모리 기반의 안전한 해시(SHA-2 / SHA-3 / SHAKE) 유틸리티입니다.
///
/// 모든 입출력은 [SensitiveDataContainer]를 통해 소유권(ownership)이 통제되며,
/// 가비지 컬렉터가 관리하는 자바 `heap` 메모리에 민감 데이터를 노출하지 않습니다.
///
/// 입력 컨테이너와 출력 컨테이너를 원샷(one-shot) FFI 함수로 전달하여
/// `entlib-native`의 다이제스트 연산을 수행합니다. 입출력 컨테이너의 생명 주기는
/// 호출자가 전달한 [SDCScopeContext]가 책임집니다.
///
/// @author Q. T. Felix
public final class Hash {

    private Hash() {
        throw new AssertionError("cannot access");
    }

    /// SHA-2 다이제스트를 계산합니다.
    ///
    /// @param length 다이제스트 비트 길이 (224, 256, 384, 512)
    /// @param scope  데이터 생명주기를 통제할 스코프 컨텍스트
    /// @param input  해시 대상 컨테이너
    /// @return 다이제스트 결과가 담긴 새로운 보안 컨테이너 (스코프에 귀속됨)
    public static SensitiveDataContainer sha2(
            final int length,
            final @NotNull SDCScopeContext scope,
            final @NotNull SensitiveDataContainer input
    ) throws ELIBSecurityProcessException {
        final int digestBytes = digestByteSize(length);
        validate(scope, input);

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

    /// SHA-3 다이제스트를 계산합니다.
    ///
    /// @param length 다이제스트 비트 길이 (224, 256, 384, 512)
    /// @param scope  데이터 생명주기를 통제할 스코프 컨텍스트
    /// @param input  해시 대상 컨테이너
    /// @return 다이제스트 결과가 담긴 새로운 보안 컨테이너 (스코프에 귀속됨)
    public static SensitiveDataContainer sha3(
            final int length,
            final @NotNull SDCScopeContext scope,
            final @NotNull SensitiveDataContainer input
    ) throws ELIBSecurityProcessException {
        final int digestBytes = digestByteSize(length);
        validate(scope, input);

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

    /// SHAKE 가변 길이 출력 함수(XOF)를 계산합니다.
    ///
    /// @param length     SHAKE 변형 (128 또는 256)
    /// @param byteOutLen 생성할 출력 바이트 길이
    /// @param scope      데이터 생명주기를 통제할 스코프 컨텍스트
    /// @param input      해시 대상 컨테이너
    /// @return SHAKE 출력이 담긴 새로운 보안 컨테이너 (스코프에 귀속됨)
    public static SensitiveDataContainer sha3Shake(
            final int length,
            final long byteOutLen,
            final @NotNull SDCScopeContext scope,
            final @NotNull SensitiveDataContainer input
    ) throws ELIBSecurityProcessException {
        if (length != 128 && length != 256)
            throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHAKE 변형입니다: " + length);
        if (byteOutLen <= 0 || byteOutLen > Integer.MAX_VALUE)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 SHAKE 출력 길이입니다: " + byteOutLen);
        validate(scope, input);

        final SensitiveDataContainer output = scope.allocate((int) byteOutLen);
        try (Arena transientArena = Arena.ofConfined()) {
            final MemorySegment in = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            final MemorySegment out = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            final NativeProcessResult<Long> result = switch (length) {
                case 128 -> ConstableFactory.Hash.SHA3.shake128(in, out);
                case 256 -> ConstableFactory.Hash.SHA3.shake256(in, out);
                default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHAKE 변형입니다: " + length);
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

    private static int digestByteSize(final int length) throws ELIBSecurityProcessException {
        return switch (length) {
            case 224 -> 28;
            case 256 -> 32;
            case 384 -> 48;
            case 512 -> 64;
            default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 다이제스트 길이입니다: " + length);
        };
    }

    private static void validate(final SDCScopeContext scope, final SensitiveDataContainer input) {
        if (scope == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 스코프 컨텍스트입니다!");
        if (input == null || !InternalNativeBridge.unwrapArena(input).scope().isAlive())
            throw new ELIBSecurityIllegalArgumentException("유효하지 않거나 이미 소거된 입력 컨테이너입니다!");
    }
}
