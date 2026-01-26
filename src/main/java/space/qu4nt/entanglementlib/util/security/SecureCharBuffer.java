/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.security;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;
import space.qu4nt.entanglementlib.CallerResponsibility;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

/**
 * 메모리 내 민감 정보(sensitive data)의 잔존 시간을 최소화하고, 참조 누수(reference leak)를 방지하기 위한
 * 스레드 안전(thread-safe)한 보안 컨테이너 클래스입니다.
 * <p>
 * 양자-내성 암호(Post-Quantum Cryptography, PQC)의 개인 키 혹은 대칭키와 같이 높은 보안 수준이 요구되는 데이터를
 * 힙 메모리 상에서 안전하게 격리 및 소거하는 메커니즘을 제공합니다.
 * <p>
 * 다음의 주요 특징을 가집니다.
 * <ul>
 *   <li><b>참조 격리 (Reference Isolation):</b> 내부 버퍼의 참조를 직접 반환하지 않고,
 *   {@link Consumer}를 통한 제어의 역전(IoC) 패턴을 사용하여 접근 범위를 제한합니다.</li>
 *   <li><b>최적화 방지 소거 (Anti-DSE Zeroing):</b> 컴파일러의 <i>Dead Store Elimination</i> 최적화를 우회하여
 *   물리적 메모리 상의 데이터를 확실하게 덮어씁니다.</li>
 *   <li><b>원자적 상태 관리 (Atomic State Management):</b> {@link ReadWriteLock}을 사용하여 데이터
 *   사용(read)과 파기(write) 작업 간의 상호 배제(mutual exclusion)를 보장합니다.</li>
 * </ul>
 * 이 클래스는 {@link AutoCloseable}을 구현하기 때문에 {@code try-with-resources} 블록 내에서 사용되어야 합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public final class SecureCharBuffer implements AutoCloseable {

    /**
     * 민감 데이터를 저장하는 내부 버퍼입니다.
     * <p>
     * {@code transient} 키워드를 사용하여 직렬화 과정에서 평문 데이터가
     * 영구 저장소나 네트워크 스트림으로 유출되는 것을 방지합니다.
     */
    private final transient char[] buffer;

    /**
     * 버퍼의 파기 여부를 나타내는 원자적 플래그입니다.
     * 상태 전이는 {@code False to True} 방향으로만 발생하며, 이는 비가역적입니다.
     */
    private final AtomicBoolean destroyed = new AtomicBoolean(false);

    /**
     * 동시성 제어를 위한 읽기-쓰기 잠금(Read-Write Lock)입니다.
     * <p>
     * 데이터의 유효성을 보장하기 위해 사용 시에는 {@code ReadLock}을,
     * 파기 시에는 {@code WriteLock}을 획득하여 경쟁 상태를 방지합니다.
     */
    private final ReadWriteLock rwLock = new ReentrantReadWriteLock();

    /**
     * 외부의 문자 배열을 복제하여 안전한 내부 버퍼를 생성합니다.
     * 인스턴스 {@link #buffer} 에 복사본을 할당합니다.
     * <p>
     * 원본 배열에 대한 외부 참조가 내부 버퍼의 무결성에 영향을 미치지 않도록,
     * {@code O(N)} 시간 복잡도를 갖는 심층 복사를 수행하여 데이터를 격리합니다.
     *
     * @param source 민감 데이터의 원본 배열. {@code null}일 경우 빈 배열로 초기화
     */
    public SecureCharBuffer(char[] source) {
        if (source == null) {
            this.buffer = new char[0];
        } else {
            this.buffer = source.clone();
        }
    }

    /**
     * 지정된 길이만큼의 무작위 비밀번호를 생성하여 내부 버퍼에 저장하는 메소드입니다.
     *
     * @param length 생성할 비밀번호의 길이 (0 이상)
     */
    public SecureCharBuffer(@Range(from = 0, to = Integer.MAX_VALUE) int length) {
        this.buffer = Password.generate(length).clone();
    }

    /**
     * 내부 버퍼의 내용을 {@code UTF-8} 인코딩된 바이트 배열로 변환하여 반환하는 메소드입니다.
     * <p>
     * 변환 과정에서 생성된 임시 버퍼들은 즉시 소거되어 메모리에 잔존하지 않도록 처리됩니다.
     * <p>
     * 결과의 원본을 반환하기 때문에 작업 종료 시 호출자 측에서 반드시 소거 작업을 수행해야 하며,
     * 이 메소드는 반드시 콜백 안에서 사용되어야 합니다.
     *
     * @return {@code UTF-8}로 인코딩된 바이트 배열
     */
    @CallerResponsibility("원본을 반환하기 때문에 소거 필요")
    @Contract("-> !null")
    byte[] toBytes() {
        final CharBuffer charBuffer = CharBuffer.wrap(buffer);
        final ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);

        byte @NotNull [] rBytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(rBytes);

        KeyDestroyHelper.zeroing(byteBuffer.array());
        KeyDestroyHelper.zeroing(charBuffer.array());

        return rBytes;
    }

    /**
     * {@link #toBytes()} 메소드를 통해 내부 버퍼에 접근하여 바이트 배열로 변환한 뒤 안전하게 작업을 수행합니다.
     * <p>
     * 버퍼의 참조를 반환하는 기존 방식({@code f: S -> R}) 대신, 작업을 버퍼의 스코프 내부로 주입하는 방식
     * ({@code f: (R -> void) -> void})을 채택하여 참조 탈출을 원천적으로 차단합니다.
     * <p>
     * {@code ReadLock}을 획득하여 실행되므로, 이 메소드가 수행되는 동안에는
     * {@link #wipe()} 메소드에 의한 데이터 파기가 발생하지 않음이 보장됩니다.
     *
     * @see #use(Consumer) 문자 배열 작업을 수행하고자 하는 경우
     * @param action 버퍼를 인자로 받아 수행할 작업(Consumer)
     *               이 작업은 버퍼의 참조를 외부로 유출하면 안됌
     * @throws IllegalStateException 버퍼가 이미 파기된 상태에서 호출된 경우
     */
    public void useWithBytes(Consumer<@CallerResponsibility byte[]> action) {
        Lock readLock = rwLock.readLock();
        readLock.lock();
        try {
            if (destroyed.get())
                throw new IllegalStateException("Access denied: Buffer has been destroyed.");
            // 콜백 내부에서만 버퍼 접근 가능
            action.accept(toBytes());
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 내부 버퍼에 접근하여 안전하게 작업을 수행합니다.
     * <p>
     * 버퍼의 참조를 반환하는 기존 방식({@code f: S -> R}) 대신, 작업을 버퍼의 스코프 내부로 주입하는 방식
     * ({@code f: (R -> void) -> void})을 채택하여 참조 탈출을 원천적으로 차단합니다.
     * <p>
     * {@code ReadLock}을 획득하여 실행되므로, 이 메소드가 수행되는 동안에는
     * {@link #wipe()} 메소드에 의한 데이터 파기가 발생하지 않음이 보장됩니다.
     *
     * @param action 버퍼 바이트 배열를 인자로 받아 수행할 작업(Consumer)
     *               이 작업은 버퍼의 참조를 외부로 유출하면 안됌
     * @throws IllegalStateException 버퍼가 이미 파기된 상태에서 호출된 경우
     */
    public void use(Consumer<@CallerResponsibility char[]> action) {
        Lock readLock = rwLock.readLock();
        readLock.lock();
        try {
            if (destroyed.get())
                throw new IllegalStateException("Access denied: Buffer has been destroyed.");
            // 콜백 내부에서만 버퍼 접근 가능
            action.accept(buffer);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 메모리 상의 민감 데이터를 명시적으로 영소거(zeroing)합니다.
     * <p>
     * 이 메소드는 {@code WriteLock}을 획득하여 수행되므로, 다른 스레드가 데이터를 사용 중일 때는
     * 대기하며, 파기가 완료될 때까지 새로운 접근을 차단합니다.
     * <p>
     * <b>보안 구현 상세:</b><br>
     * 단순한 {@code Arrays.fill} 호출은 JIT 컴파일러의 <i>Dead Store Elimination</i> 최적화에 의해
     * 제거될 위험이 있다. 이를 방지하기 위해 데이터에 임의의 값을 덮어쓰고 다시 0으로 초기화하는
     * 다단계 소거 로직을 수행하여, 메모리 쓰기 작업의 부수 효과를 강제합니다.
     */
    public void wipe() {
        // 이미 파기되었으면 중복 실행 방지 (CAS 연산)
        if (!destroyed.compareAndSet(false, true))
            return;

        Lock writeLock = rwLock.writeLock();
        writeLock.lock();
        try {
            // 1단계: 0으로 덮어쓰기 (기본 소거)
            KeyDestroyHelper.zeroing(buffer);

            // 2단계: 보안 강화를 위한 추가 덮어쓰기 (Anti-Optimization)
            // 컴파일러가 최적화(코드 삭제)를 수행하지 못하도록 데이터 의존성 생성
            for (int i = 0; i < buffer.length; i++)
                buffer[i] = (char) (i % 0xFF); // 의미 없는 데이터 쓰기
            KeyDestroyHelper.zeroing(buffer); // 다시 소거
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * 리소스 해제 시 자동으로 호출되어 {@link #wipe()}를 수행합니다.
     * <p>
     * {@code try-with-resources} 구문을 사용할 경우, 블록을 벗어나는 즉시
     * 메모리 소거가 수행됨을 보장합니다.
     * <p>
     * 해당 방식을 사용하지 않을 경우, 작업 완료 시 수동 소거가 필요합니다.
     */
    @Override
    public void close() {
        wipe();
    }

    /**
     * 현재 버퍼가 파기되었는지 확인합니다.
     *
     * @return 파기되었으면 {@code true}, 유효하면 {@code false}
     */
    public boolean isDestroyed() {
        return destroyed.get();
    }
}
