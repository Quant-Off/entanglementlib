/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.entlibnative;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/// [SensitiveDataContainer]의 동시성 이슈를 검증하기 위한 테스트 클래스입니다.
/// [`bindings`][SensitiveDataContainer#bindings] 리스트의 복합 
/// 연산(iterate-then-Clear)에 대한 Thread-Safety를 집중적으로 테스트합니다.
/// 
/// @author Q. T. Felix
/// @since 1.1.0
@Slf4j
@SuppressWarnings({"all"})
class SDCBindingsConcurrencyTest {

    // 테스트 반복 횟수 (동시성 문제는 간헐적으로 발생해서 반복 테스트)
    private static final int REPEAT_COUNT = 10;
    private static final int THREAD_COUNT = 16;
    private static final int CHILDREN_COUNT = 100;

    /// # Scenario 1
    /// 
    /// 다수의 스레드가 동시에 close()를 호출할 때의 안정성 테스트
    /// 
    /// # Expected
    ///
    /// [`bindings`][SensitiveDataContainer#bindings] 리스트에 대한 접근 경합으로
    /// 인해 [IndexOutOfBoundsException] 등이 발생할 가능성이 있음.
    /// (현재 구현상 [`close()`][SensitiveDataContainer#close()] 메소드는 동기화
    /// 블록 없이 인덱스로 접근하므로 실패할 확률이 높음)
    @RepeatedTest(REPEAT_COUNT)
    @DisplayName("동시 close() 호출 시 예외 발생 여부 검증 (Race Condition)")
    void testConcurrentClose() throws InterruptedException, EntLibSecureIllegalStateException {
        // Given: 많은 자식 컨테이너를 가진 부모 컨테이너 생성
        SensitiveDataContainer parent = new SensitiveDataContainer(1024);
        for (int i = 0; i < CHILDREN_COUNT; i++) {
            parent.addContainerData(new SensitiveDataContainer(128));
        }

        ExecutorService executorService = Executors.newFixedThreadPool(THREAD_COUNT);
        CountDownLatch latch = new CountDownLatch(1);
        AtomicInteger exceptionCount = new AtomicInteger(0);

        // When: 동시에 여러 스레드에서 close() 호출
        for (int i = 0; i < THREAD_COUNT; i++) {
            executorService.submit(() -> {
                try {
                    latch.await(); // 모든 스레드가 준비될 때까지 대기
                    parent.close();
                } catch (Exception e) {
                    // 예외 발생 시 카운트 (주로 IndexOutOfBoundsException 예상)
                    exceptionCount.incrementAndGet();
                    e.printStackTrace(); // 디버깅용 로그
                }
            });
        }

        latch.countDown(); // 땅! 모든 스레드 시작
        executorService.shutdown();
        boolean finished = executorService.awaitTermination(5, TimeUnit.SECONDS);

        // Then
        assertTrue(finished, "테스트가 시간 내에 종료되지 않았습니다!");
        assertEquals(0, exceptionCount.get(),
                "동시 close() 호출 중 예외가 발생했습니다. Thread-Safety가 보장되지 않습니다!");
    }

    /// # Scenario 2
    ///
    /// [`close()`][SensitiveDataContainer#close()]가 진행되는 동안
    /// [`addContainerData()`][SensitiveDataContainer#addContainerData()]가
    /// 호출될 때의 무결성 테스트
    ///
    /// # Expected
    ///
    /// 1. 닫히는 도중 추가된 데이터가 `close()` 되지 않고 유실(leak)되는지 확인
    /// 2. 반복문 인덱스 접근 중 리스트 사이즈 변경으로 인한 예외 확인
    ///
    @Test
    @DisplayName("close()와 addContainerData() 동시 수행 시 무결성 검증")
    void testAddWhileClosing() throws InterruptedException {
        // Given
        SensitiveDataContainer parent = new SensitiveDataContainer(1024);
        int addCount = 1000;

        ExecutorService executorService = Executors.newFixedThreadPool(2);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicInteger successAddCount = new AtomicInteger(0);
        AtomicInteger exceptionCount = new AtomicInteger(0);

        // Thread 1: 지속적으로 데이터 추가
        Runnable adder = () -> {
            try {
                startLatch.await();
                for (int i = 0; i < addCount; i++) {
                    // 이미 닫힌 경우(Native Memory 해제됨) IllegalStateException 등이 발생할 수 있음
                    try {
                        parent.addContainerData(new SensitiveDataContainer(10));
                        successAddCount.incrementAndGet();
                    } catch (Exception e) {
                        // close()에 의해 Arena가 닫힌 후 추가 시도는 실패하는 것이 정상일 수 있는데
                        // 리스트 관련 예외(IndexOutOfBounds 등)는 비정상임
                        if (!(e instanceof IllegalStateException)) {
                            exceptionCount.incrementAndGet();
                        }
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };

        // Thread 2: 약간의 지연 후 close() 수행
        Runnable closer = () -> {
            try {
                startLatch.await();
                Thread.sleep(2); // 추가 작업이 어느 정도 진행된 후 닫기 시도
                parent.close();
            } catch (Exception e) {
                exceptionCount.incrementAndGet();
                e.printStackTrace();
            }
        };

        // When
        executorService.submit(adder);
        executorService.submit(closer);

        startLatch.countDown();
        executorService.shutdown();
        executorService.awaitTermination(5, TimeUnit.SECONDS);

        // Then
        // 만약 리스트 동기화가 제대로 안 되었다면 여기서 예외가 포착될 것임
        assertEquals(0, exceptionCount.get(),
                "close()와 add() 경합 중 예외가 발생했습니다!");
    }
}