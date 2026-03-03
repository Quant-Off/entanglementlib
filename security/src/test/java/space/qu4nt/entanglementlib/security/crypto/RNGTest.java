package space.qu4nt.entanglementlib.security.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityNativeCritical;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.crypto.rng.RNG;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.entlibnative.Function;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import static org.junit.jupiter.api.Assertions.*;

class RNGTest {

    @BeforeAll
    static void setUp() {
        // 테스트 클래스 로드 시 1회만 네이티브 라이브러리를 초기화하여 성능 최적화
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        new NativeSpecContext("/Library/Quant/Repository/projects/entanglementlib/entlib-native/target/debug", "entlib_native_ffi",
                                Function.chain(
                                        Function.withCalleeSecureBuffer(),
                                        Function.withCallerSecureBuffer(),
                                        Function.withRNG())),
                        HeuristicArenaFactory.ArenaMode.CONFINED)
        );
    }

    @Test
    @DisplayName("로컬 하드웨어(local hardware) 기반 혼합 난수 생성 및 소거(zeroize) 검증")
    void hardwareRngLifecycleAndZeroizeTest() throws ELIBSecurityProcessException {
        final long PQC_KEY_LENGTH = 32; // 양자-내성 암호화(post-quantum cryptography) 키 길이를 가정한 32바이트
        MemorySegment capturedSegment;

        // 보안 스코프(secure scope) 컨텍스트 생성 및 난수 할당
        try (SDCScopeContext scope = new SDCScopeContext()) {
            SensitiveDataContainer sdc = RNG.generateRNG(RNG.LOCAL_HARDWARE, scope, PQC_KEY_LENGTH);

            assertNotNull(sdc, "생성된 민감 데이터 컨테이너(sensitive data container)는 null이 아니어야 합니다.");
            capturedSegment = sdc.getMemorySegment();

            // arena 및 메모리 세그먼트 유효성 검증
            assertTrue(sdc.getArena().scope().isAlive(), "스코프(scope) 내부에서는 Arena가 활성화 상태여야 합니다.");
            assertEquals(PQC_KEY_LENGTH, capturedSegment.byteSize(), "생성된 난수의 크기가 요청한 길이와 일치해야 합니다.");

            // 엔트로피 데이터 존재 여부 검증 (모두 0인지 확인)
            boolean hasNonZero = false;
            for (long i = 0; i < PQC_KEY_LENGTH; i++) {
                if (capturedSegment.get(ValueLayout.JAVA_BYTE, i) != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "초기화된 난수 버퍼가 모두 0일 수는 없습니다. (엔트로피 부족 의심)");
        } // try-with-resources 종료 시 scope.close() 호출 -> SDC 소거(zeroize) 자동 수행

        // 스코프 종료 후 자원 파기 검증
        // SDCScopeContext가 닫히면서 소속된 모든 컨테이너의 아레나가 닫히고 네이티브 포인터가 무효화되어야 함
        assertFalse(capturedSegment.scope().isAlive(), "컨텍스트 종료 후에는 Arena가 반드시 닫혀야 합니다.");

        // 메모리 영역 강제 접근 시 예외 발생 검증
        assertThrows(IllegalStateException.class, () -> {
            capturedSegment.get(ValueLayout.JAVA_BYTE, 0);
        }, "해제 및 소거(zeroize)된 네이티브 메모리에 접근 시도 시 예외가 발생해야 합니다.");
    }

    @Test
    @DisplayName("양자 네트워크(quantum network) 기반 혼합 난수 생성 에러 핸들링 검증")
    void quantumNetworkRngErrorHandlingTest() throws ELIBSecurityProcessException {
        // 양자 네트워크 특성상 외부 통신 환경에 따라 실패할 수 있어서 생성 성공 여부 또는
        // 네트워크 타임아웃/파싱 에러 시 ELIBSecurityNativeCritical 예외가 올바르게 전파되는지 검증해야됌
        try (SDCScopeContext scope = new SDCScopeContext()) {
            try {
                SensitiveDataContainer sdc = RNG.generateRNG(RNG.QUANTUM_NETWORK, scope, 64);
                assertNotNull(sdc);
                assertTrue(sdc.getArena().scope().isAlive());
            } catch (ELIBSecurityNativeCritical e) {
                // 통신 실패 시 던져지는 예외 메시지가 우리가 정의한 규칙에 부합하는지 확인
                String msg = e.getMessage();
                assertTrue(
                        msg.contains("네트워크(network)") || msg.contains("파싱(parsing)") || msg.contains("알 수 없는"),
                        "예상치 못한 네이티브 에러가 발생했습니다: " + msg
                );
            }
        }
    }
}