package space.qu4nt.entanglementlib.security.crypto.encode;

import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.ConstableFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeProcessResult;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/// 네이티브 메모리 기반의 안전한 `Hex` 인코딩 및 디코딩 유틸리티입니다.
/// 모든 입출력은 [SensitiveDataContainer]를 통해 소유권(ownership)이 통제되며,
/// 가비지 컬렉터가 관리하는 자바 `heap` 메모리에 민감 데이터를 노출하지 않습니다.
public final class Hex {

    private Hex() {
        throw new AssertionError("cannot access");
    }

    /// 제공된 보안 컨테이너의 데이터를 Hex로 인코딩합니다.
    /// Zero-Trust 원칙에 따라 JVM `Heap` 메모리를 거치지 않고 오직 `Off-Heap` 컨테이너
    /// 간의 연산만 허용합니다.
    ///
    /// # Security Note
    /// 입력 컨테이너(input)와 출력 컨테이너(output)의 생명 주기는 이 메소드를 호출한
    /// 외부의 컨텍스트 [SDCScopeContext] 또는 `try-with-resources`가 책임집니다.
    ///
    /// @param scope 데이터 상호 작용을 수행할 보안 컨테이너 스코프
    /// @param input 인코딩 타겟 컨테이너
    /// @return Hex 인코딩 결과가 담긴 새로운 보안 컨테이너
    public static SensitiveDataContainer encode(final SDCScopeContext scope, final SensitiveDataContainer input) throws ELIBSecurityProcessException {
        if (scope == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 스코프 컨텍스트입니다!");
        if (input == null || !InternalNativeBridge.unwrapArena(input).scope().isAlive())
            throw new ELIBSecurityIllegalArgumentException("유효하지 않거나 이미 소거된 입력 컨테이너입니다!");

        final long inputLen = InternalNativeBridge.unwrapMemorySegment(input).byteSize();
        if (inputLen > Long.MAX_VALUE / 2)
            throw new ELIBSecurityProcessException("Base64 인코딩 허용 메모리 한계를 초과했습니다!");
        // Hex 인코딩 시 필요한 정확한 버퍼 크기 계산 (원본 * 2)
        final long required = inputLen * 2;
        final SensitiveDataContainer output = scope.allocate(required);

        try (Arena transientArena = Arena.ofConfined()) {
            MemorySegment inputFFIStandard = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            MemorySegment outputFFIStandard = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            NativeProcessResult<Long> result = ConstableFactory.Hex.hexEncode(inputFFIStandard, outputFFIStandard);
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 Hex 인코딩 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (Throwable t) {
            if (t instanceof ELIBSecurityProcessException) throw (ELIBSecurityProcessException) t;
            throw new ELIBSecurityProcessException("Hex 인코딩 FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }

    /// `Base64`로 인코딩된 민감 데이터를 디코딩하는 메소드입니다.
    /// Zero-Trust 원칙에 따라 JVM `Heap` 메모리를 거치지 않고 오직 `Off-Heap` 컨테이너
    /// 간의 연산만 허용합니다.
    ///
    /// # Security Note
    /// 입력 컨테이너(input)와 출력 컨테이너(output)의 생명 주기는 이 메소드를 호출한
    /// 외부의 컨텍스트 [SDCScopeContext] 또는 `try-with-resources`가 책임집니다.
    ///
    /// @param scope 데이터 생명주기를 통제할 UCA 스코프 컨텍스트
    /// @param input Base64로 인코딩된 데이터를 담고 있는 입력 컨테이너
    /// @return 디코딩된 원본 데이터가 담긴 새로운 보안 컨테이너 (스코프에 귀속됨)
    /// @throws ELIBSecurityProcessException 네이티브 연산 실패 또는 메모리 할당 오류 시 발생
    public static SensitiveDataContainer decode(final SDCScopeContext scope, final SensitiveDataContainer input) throws ELIBSecurityProcessException {
        if (scope == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 스코프 컨텍스트입니다!");
        if (input == null || !InternalNativeBridge.unwrapArena(input).scope().isAlive())
            throw new ELIBSecurityIllegalArgumentException("유효하지 않거나 이미 소거된 입력 컨테이너입니다!");

        final long inputLen = InternalNativeBridge.unwrapMemorySegment(input).byteSize();

        // 비밀 데이터가 아니므로 일반 분기문을 사용
        // 홀수 길이를 즉각 거부하여 침묵적 절삭(Truncation) 방지
        if (inputLen % 2 != 0)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 Hex 인코딩 데이터입니다 (홀수 길이)!");

        // Hex 디코딩 시 필요한 정확한 버퍼 크기 계산 (원본 / 2)
        // (디코딩은 크기가 줄어들므로 inputLen에 대한 최대 한계(오버플로우) 체크가 생략됩니다)
        final long required = inputLen / 2;
        final SensitiveDataContainer output = scope.allocate(required);

        try (Arena transientArena = Arena.ofConfined()) {
            MemorySegment inputFFIStandard = ConstableFactory.Std.allocateJOStandard(transientArena, input);
            MemorySegment outputFFIStandard = ConstableFactory.Std.allocateJOStandard(transientArena, output);

            NativeProcessResult<Long> result = ConstableFactory.Hex.hexDecode(inputFFIStandard, outputFFIStandard);
            if (!result.isSuccess())
                throw new ELIBSecurityProcessException("Rust 네이티브 측 Hex 디코딩 실패 (상태 코드: " + result.getStatusCode() + ")");
        } catch (Throwable t) {
            if (t instanceof ELIBSecurityProcessException) throw (ELIBSecurityProcessException) t;
            throw new ELIBSecurityProcessException("Hex 디코딩 FFI 호출 중 치명적 예외가 발생했습니다!", t);
        }
        return output;
    }
}