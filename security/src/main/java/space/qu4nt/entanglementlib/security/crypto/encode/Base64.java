package space.qu4nt.entanglementlib.security.crypto.encode;

import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.EntLibNativeManager;
import space.qu4nt.entanglementlib.security.entlibnative.Function;

import java.lang.foreign.MemorySegment;

/**
 * 네이티브 메모리(native memory) 기반의 안전한 Base64 인코딩 및 디코딩 유틸리티입니다.
 * 모든 입출력은 {@link SensitiveDataContainer}를 통해 소유권(ownership)이 통제되며,
 * 가비지 컬렉터(garbage collector)가 관리하는 자바 힙(java heap) 메모리에 민감 데이터를 노출하지 않습니다.
 */
public final class Base64 {

    private Base64() {
        throw new AssertionError("유틸리티 클래스는 인스턴스화할 수 없습니다.");
    }

    /**
     * 제공된 보안 컨테이너의 데이터를 Base64로 인코딩합니다.
     * 반환된 새 컨테이너는 호출자(caller)가 소유권을 가지며, 세션 종료 시 명시적으로 소거해야 합니다.
     *
     * @param input 원본 데이터가 담긴 보안 컨테이너
     * @return Base64 인코딩 결과가 담긴 새로운 보안 컨테이너
     */
    public static SensitiveDataContainer encode(final SensitiveDataContainer input) {
        if (input == null || !InternalNativeBridge.unwrapArena(input).scope().isAlive()) {
            throw new IllegalArgumentException("유효하지 않거나 이미 소거된 입력 컨테이너입니다.");
        }

        final long inputLen = InternalNativeBridge.unwrapMemorySegment(input).byteSize();
        final int required = (int) (((inputLen + 2) / 3) * 4);

        SensitiveDataContainer output = new SensitiveDataContainer(required);

        try {
            long result = (long) EntLibNativeManager.call(Function.Base64_encode).invokeExact(
                    InternalNativeBridge.unwrapMemorySegment(input),
                    inputLen,
                    InternalNativeBridge.unwrapMemorySegment(output),
                    (long) required
            );

            if (result < 0) {
                output.close();
                throw new RuntimeException("인코딩 중 네이티브 오류 발생 (error code): " + result);
            }

            return output;
        } catch (Throwable t) {
            output.close();
            throw new RuntimeException("FFM API 인코딩 호출 실패", t);
        }
    }

    /**
     * 제공된 보안 컨테이너의 Base64 데이터를 디코딩합니다.
     * 반환된 새 컨테이너는 호출자(caller)가 소유권을 가지며, 세션 종료 시 명시적으로 소거해야 합니다.
     *
     * @param input Base64 인코딩 데이터가 담긴 보안 컨테이너
     * @return 디코딩된 원본 데이터가 담긴 새로운 보안 컨테이너
     */
    public static SensitiveDataContainer decode(final SensitiveDataContainer input) {
        if (input == null || !InternalNativeBridge.unwrapArena(input).scope().isAlive()) {
            throw new IllegalArgumentException("유효하지 않거나 이미 소거된 입력 컨테이너입니다.");
        }

        final long inputLen = InternalNativeBridge.unwrapMemorySegment(input).byteSize();
        final int maxRequired = (int) ((inputLen / 4 + 1) * 3);

        // 임시 컨테이너 생성 (try-with-resources로 자동 소거 보장)
        try (SensitiveDataContainer tempOutput = new SensitiveDataContainer(maxRequired)) {

            long result = (long) EntLibNativeManager.call(Function.Base64_decode).invokeExact(
                    InternalNativeBridge.unwrapMemorySegment(input),
                    inputLen,
                    InternalNativeBridge.unwrapMemorySegment(tempOutput),
                    (long) maxRequired
            );

            if (result < 0) {
                throw new RuntimeException("디코딩 중 네이티브 오류 발생 (error code): " + result);
            }

            // 실제 크기에 맞는 반환용 컨테이너 생성 (소유권 이전용)
            // result(실제 길이)만큼만 할당
            SensitiveDataContainer exactOutput = new SensitiveDataContainer((int) result);

            try {
                // 데이터 복사
                MemorySegment src = InternalNativeBridge.unwrapMemorySegment(tempOutput);
                MemorySegment dst = InternalNativeBridge.unwrapMemorySegment(exactOutput);
                MemorySegment.copy(src, 0, dst, 0, result);
                return exactOutput;
            } catch (Exception e) {
                exactOutput.close(); // 복사 중 예외 시 반환용 컨테이너도 닫음
                throw e;
            }
            // 메소드 종료 시 tempOutput.close()가 자동 호출

        } catch (Throwable t) {
            throw new RuntimeException("FFM API 디코딩 호출 실패", t);
        }
    }
}