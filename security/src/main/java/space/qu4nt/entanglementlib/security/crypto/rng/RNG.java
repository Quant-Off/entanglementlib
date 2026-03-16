package space.qu4nt.entanglementlib.security.crypto.rng;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityNativeCritical;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.NativeLinker;
import space.qu4nt.entanglementlib.security.entlibnative.NativeComponent;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/// 하드웨어 진난수 및 양자 난수(quantum random number) 생성 인터페이스입니다.
/// 모든 반환 데이터는 네이티브 스코프 내에서 완벽한 데이터 소거(zeroize)가 보장됩니다.
///
/// @author Q. T. Felix
public final class RNG {

    public static final byte LOCAL_HARDWARE = (byte) 0;
    public static final byte QUANTUM_NETWORK = (byte) 1;

    /// 지정된 엔트로피 전략(entropy strategy)에 따라 난수를 생성하고 컨테이너에 바인딩합니다.
    ///
    /// @param entropyStrategy 난수 생성 전략 (로컬 하드웨어 또는 양자 네트워크)
    /// @param scope           보안 데이터 생명주기를 관리하는 컨텍스트(context)
    /// @param length          생성할 난수의 바이트 길이
    /// @return `heap` 오염 없이 난수 데이터를 소유하는 민감 데이터 컨테이너
    /// @throws ELIBSecurityProcessException 난수 생성 또는 복사 중 에러 발생 시
    public static SensitiveDataContainer generateRNG(final byte entropyStrategy,
                                                     final @NotNull SDCScopeContext scope,
                                                     final long length) throws ELIBSecurityProcessException {

        // FFI 호출에 필요한 파라미터 및 포인터를 임시 관리하기 위한 로컬 아레나(arena)
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment errFlag = localArena.allocate(ValueLayout.JAVA_BYTE);

            // 혼합 난수 생성기(mixed rng) 인스턴스 초기화
            MemorySegment rngPtr = (MemorySegment) NativeLinker.call(NativeComponent.RNG_MIXED_New_With_Strategy)
                    .invokeExact(entropyStrategy, errFlag);
            checkError(errFlag.get(ValueLayout.JAVA_BYTE, 0));

            MemorySegment secureBufPtr = null;
            try {
                // 난수 버퍼 생성
                secureBufPtr = (MemorySegment) NativeLinker.call(NativeComponent.RNG_MIXED_Generate)
                        .invokeExact(rngPtr, length, errFlag);
                checkError(errFlag.get(ValueLayout.JAVA_BYTE, 0));

                // 러스트 영역의 보안 버퍼(secure buffer)에서 실제 데이터 포인터 추출
                MemorySegment dataPtr = (MemorySegment) NativeLinker.call(NativeComponent.Callee_Secure_Buffer_Data)
                        .invokeExact(secureBufPtr);
                MemorySegment nativeDataSegment = dataPtr.reinterpret(length);

                // 컨텍스트를 통한 SDC 할당
                SensitiveDataContainer sdc = scope.allocate((int) length);

                // heap 배열을 거치지 않고 네이티브 대 네이티브로 직접 메모리 복사 수행
                MemorySegment.copy(nativeDataSegment, 0, InternalNativeBridge.unwrapMemorySegment(sdc), 0, length);

                return sdc;
            } finally {
                // 러스트 힙에 할당된 포인터의 강제 해제 및 소거 유도
                if (secureBufPtr != null && !secureBufPtr.equals(MemorySegment.NULL)) {
                    NativeLinker.call(NativeComponent.Callee_Secure_Buffer_Free).invokeExact(secureBufPtr);
                }
                if (rngPtr != null && !rngPtr.equals(MemorySegment.NULL)) {
                    NativeLinker.call(NativeComponent.RNG_MIXED_Free).invokeExact(rngPtr);
                }
            }
        } catch (Throwable e) {
            throw new ELIBSecurityProcessException("네이티브 브릿지를 통한 난수 생성에 실패했습니다.", e);
        }
    }

    // Q. T. Felix TODO: 좀 더 고차원적인 구현
    private static void checkError(byte errorCode) {
        if (errorCode == 0) return;
        throw switch (errorCode) {
            case 1 -> new ELIBSecurityNativeCritical("지원하지 않는 하드웨어(hardware) 환경입니다!");
            case 2 -> new ELIBSecurityNativeCritical("엔트로피(entropy)가 고갈되었습니다!");
            case 3 -> new ELIBSecurityNativeCritical("잘못된 메모리 포인터(pointer) 참조입니다!");
            case 4 -> new ELIBSecurityNativeCritical("양자 난수 생성기 네트워크(network) 통신에 실패했습니다!");
            case 5 -> new ELIBSecurityNativeCritical("양자 난수 데이터 파싱(parsing) 에러가 발생했습니다!");
            case 6 -> new ELIBSecurityNativeCritical("잘못된 파라미터(parameter)가 전달되었습니다!");
            default -> new ELIBSecurityNativeCritical("알 수 없는 네이티브(native) 에러 코드: " + errorCode);
        };
    }
}