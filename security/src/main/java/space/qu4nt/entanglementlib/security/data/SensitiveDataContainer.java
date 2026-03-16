/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.data;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.annotations.CallerResponsibility;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityUnsafeUsageException;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityCritical;
import space.qu4nt.entanglementlib.security.entlibnative.ConstableFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeProcessResult;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.Arrays;
import java.util.Objects;

/// `Rust`의 소유권(ownership) 개념처럼 이 클래스도 전달받은 민감 정보에 대한 소유권을 가집니다.
/// 이 클래스에 저장된 데이터는 진행중인 세션에 종속되고, 세션이 종료됨에 따라 모든 데이터가 완벽하게
/// 소거됩니다. 데이터 소거는 `entlib-native`에서 진행됩니다.
///
/// 이 객체를 통해 네이티브 함수에 필요한 데이터를 전달하거나, 함수 실행 결과를 받을 수 있습니다.
/// 이 경우 **"호출자 패턴"이 사용되며, 해당 데이터의 소거는 보장되지만 할당 해제 권한이 이 객체에
/// 부여**되어 반드시 지정된 데이터에 대한 할당 해제 함수를 호출해야 합니다.
///
/// 하지만 이 객체는 [AutoCloseable] 인터페이스를 구현함으로서 [#close()] 수행 시 호출자 측
/// 메모리 해제 함수를 자동으로 호출해줍니다.
///
/// ---
///
/// [#SensitiveDataContainer(byte\[\], boolean)] 생성자를 사용하여 전달받은 바이트 배열
/// 데이터에 대한 `heap` 소거 진행 여부를 지정할 수 있습니다. 논리 값이 `true`일 경우 데이터는
/// Java `heap` 메모리에서 즉시 소거됩니다.
///
/// # Usage
/// 이전엔 일일이 컨테이너를 연결해주어야 했습니다. 이 과정을 축약하기 위해 [SDCScopeContext]
/// 개념을 도입했습니다. 이 객체를 통해 스코프를 생성하고 내부의 전체 컨테이너에 대해 작업
/// 완료 시 안전하게 소거 및 할당 해제 작업을 자동으로 수행하도록 할 수 있습니다.
/// ```java
/// // 보안 세션 시작
/// try (SecureScopeContext scope = new SecureScopeContext()) {
///
///     // allocate raw key data
///     SensitiveDataContainer rawKey = scope.allocate(32);
///
///     // generate PQC key pair
///     SensitiveDataContainer pqcCiphertext = PQC.encapsulate(scope, rawKey);
///
///     // encode to Base64 for transmission
///     SensitiveDataContainer b64Data = Base64.encode(scope, pqcCiphertext);
///
///     // ...network transmission 또는 별도의 로직...
///
/// } // 스코프가 닫히는 순간 rawKey, pqcCiphertext, b64Data가 역순으로 완벽하게 소거
/// // 네이티브에 FFI로 넘어온 할당 해제 함수를 자동으로 호출하여 지정된 객체에 대해 모두 수행
/// ```
/// 위와 같은 사용은 통신 체계에서 매우 유용하게 사용될 수 있습니다.
///
/// 작업량이 스코프 작업에 어울리지 않을 수도 있습니다. 예를 들어, 보안 난수 생성 및 세션 내에서
/// 구조화된 경량 통신 체계를 구축할 때는 다음과 같이 사용될 수 있습니다.
/// ```java
/// SensitiveDataContainer.runScope(256, container -> {
///     // ...Secure stuff...
/// }); // 소비 패턴
///
/// int resultSize = SensitiveDataContainer.callScope(1024, container -> {
///     // ...Secure stuff...
///     return container.getMemorySegment().byteSize();
/// }); // 반환 패턴
/// ```
/// 각 메소드의 모든 작업은 `try-with-resources` 블럭 내에서 사용됩니다.
///
/// # Safety
/// 이 객체의 인스턴스를 직접 생성해야 하는 경우 다음과 같이 네이티브에 메모리 할당 해제 함수를
/// 호출하여 사용해야 합니다.
/// ```java
/// SensitiveDataContainer sdc = ...;
/// final MemorySegment ms = sdc.getMemorySegment();
/// // ...Secure stuff...
/// EntLibNativeManager.call(Function.Caller_Secure_Buffer_Wipe)
///                    .invokeExact(ms, ms.byteSize());
/// ```
/// 이 객체를 상속받아 사용되는 경우도 일관된 사용법을 따를 수 있습니다.
///
/// @author Q. T. Felix
/// @see HeuristicArenaFactory Arena 자동 할당을 수행하는 클래스
/// @see SDCScopeContext
/// @since 1.1.0
@Slf4j
public class SensitiveDataContainer implements AutoCloseable {

    @Getter(AccessLevel.PACKAGE)
    private final Arena arena;
    @Getter(AccessLevel.PACKAGE)
    private final MemorySegment memorySegment;

    /// 네이티브 메모리에 전달받은 정수 `int` 값(바이트 크기) 만큼의 메모리 세그먼트를
    /// 생성하여 이 인스턴스를 생성합니다.
    ///
    /// # Safety
    /// 이 생성자를 통해 인스턴스를 생성하면 호출자가 부담하는 보안 책임이 발생합니다.
    /// 특별한 경우가 아닌 이상 이 방식을 통한 생성은 권장하지 않습니다.
    ///
    /// 또한, 이 생성자는 제거 예정은 없으나 권장되는 사용이 아닙니다. [SDCScopeContext]를
    /// 통해 세션식 보안 작업을 수행하세요.
    ///
    /// @param allocateSize `int` 바이트 크기
    /// @see #runScope(int, SDCConsumer) 스코프 작업 종료 시 자원 소거를 보장하는 정적 메소드
    /// @see #callScope(int, SDCFunction) 스코프 작업 종료 후 자원을 소거하고 가공된 결과를 반환하는 정적 메소드
    @CallerResponsibility("try-with-resource 사용 또는 close 메소드 직접 호출 필수")
    public SensitiveDataContainer(final int allocateSize) throws ELIBSecurityProcessException {
        this.arena = HeuristicArenaFactory.intelligenceCreateArena();
        this.memorySegment = Objects.requireNonNull(arena.allocate(allocateSize));
        ConstableFactory.Std.systemCallMemoryLock(false, memorySegment); // TODO: 실제 OS 수정
    }

    /// 네이티브 메모리에 전달받은 정수 `long` 값(바이트 크기) 만큼의 메모리 세그먼트를
    /// 생성하여 이 인스턴스를 생성합니다.
    ///
    /// # Safety
    /// 이 생성자를 통해 인스턴스를 생성하면 호출자가 부담하는 보안 책임이 발생합니다.
    /// 특별한 경우가 아닌 이상 이 방식을 통한 생성은 권장하지 않습니다.
    ///
    /// 또한, 이 생성자는 제거 예정은 없으나 권장되는 사용이 아닙니다. [SDCScopeContext]를
    /// 통해 세션식 보안 작업을 수행하세요.
    ///
    /// @param allocateSize `long` 바이트 크기
    /// @see #runScope(int, SDCConsumer) 스코프 작업 종료 시 자원 소거를 보장하는 정적 메소드
    /// @see #callScope(int, SDCFunction) 스코프 작업 종료 후 자원을 소거하고 가공된 결과를 반환하는 정적 메소드
    @CallerResponsibility("try-with-resource 사용 또는 close 메소드 직접 호출 필수")
    public SensitiveDataContainer(final long allocateSize) throws ELIBSecurityProcessException {
        this.arena = HeuristicArenaFactory.intelligenceCreateArena();
        this.memorySegment = Objects.requireNonNull(arena.allocate(allocateSize));
        ConstableFactory.Std.systemCallMemoryLock(false, memorySegment); // TODO: 실제 OS 수정
    }

    /// 원본 바이트 배열을 전달받고 네이티브 메모리에 바인딩하여 이 인스턴스를 생성합니다.
    ///
    /// 생성 시점에 전달받은 원본 바이트 배열 데이터에 대한 소유권을 이 인스턴스에 넘길지 결정할 수
    /// 있습니다. 논리 값이 `true`일 경우 데이터는 즉시 소거되고, 이는 이 인스턴스가 소유권을
    /// 가질 필요가 없다는 것을 의미합니다.
    ///
    /// # Safety
    /// 이 생성자를 통해 인스턴스를 생성하면 호출자가 부담하는 보안 책임이 발생합니다.
    /// 특별한 경우가 아닌 이상 이 방식을 통한 생성은 권장하지 않습니다. 또한, 결국
    /// `heap` 메모리에 데이터를 노출하는 것은 위험합니다. `forceWipe` 플래그를
    /// `true`로 설정하는 편이 권장됩니다.
    ///
    /// 또한, 이 생성자는 제거 예정은 없으나 권장되는 사용이 아닙니다. [SDCScopeContext]를
    /// 통해 세션식 보안 작업을 수행하세요.
    ///
    /// @param from      네이티브 메모리에 바인딩할 원본 바이트 배열
    /// @param forceWipe 인스턴스에 소유권 이전 여부
    /// @see #runScope(int, SDCConsumer) 스코프 작업 종료 시 자원 소거를 보장하는 정적 메소드
    /// @see #callScope(int, SDCFunction) 스코프 작업 종료 후 자원을 소거하고 가공된 결과를 반환하는 정적 메소드
    @CallerResponsibility({
            "try-with-resource 사용 또는 close 메소드 직접 호출 필수",
            "원본 byte[] 입력 권장"
    })
    public SensitiveDataContainer(final byte @NotNull [] from, boolean forceWipe) throws ELIBSecurityProcessException {
        this.arena = HeuristicArenaFactory.intelligenceCreateArena();
        this.memorySegment = Objects.requireNonNull(arena.allocateFrom(ValueLayout.JAVA_BYTE, from));
        if (forceWipe)
            Arrays.fill(from, (byte) 0);
        ConstableFactory.Std.systemCallMemoryLock(false, memorySegment); // TODO: 실제 OS 수정
    }

    /// 보안 컨테이너의 생명주기를 자동으로 관리하는 실행 메소드입니다.
    /// Execute-Around-Pattern이 적용되어 작업 완료 즉시 메모리가 소거됨을 보장합니다.
    ///
    /// @param allocateSize 할당할 버퍼 크기
    /// @param action       컨테이너를 사용하여 수행할 보안 로직
    /// @throws ELIBSecurityProcessException 스코프 내 작업 수행 중 발생 가능한 예외
    public static void runScope(int allocateSize, SDCConsumer action) throws ELIBSecurityProcessException {
        try (SensitiveDataContainer sdc = new SensitiveDataContainer(allocateSize)) {
            action.accept(sdc);
        }
    }

    /// 보안 컨테이너를 사용하여 값을 계산하고 반환하는 실행 메소드입니다.
    /// 반환값은 민감한 데이터(`byte[]`)가 아닌, 가공된 결과물(암호화 성공 여부, 상태 코드 등)이어야 합니다.
    ///
    /// @param allocateSize 할당할 버퍼 크기
    /// @param action       컨테이너를 사용하여 수행할 계산 로직
    /// @return 계산 결과
    /// @throws ELIBSecurityProcessException     스코프 내 작업 수행 중 발생 가능한 예외
    /// @throws ELIBSecurityUnsafeUsageException 올바르지 않거나 위험한 반환 시 발생하는 예외
    public static <R> R callScope(int allocateSize, SDCFunction<R> action) throws ELIBSecurityProcessException, ELIBSecurityUnsafeUsageException {
        try (SensitiveDataContainer sdc = new SensitiveDataContainer(allocateSize)) {
            R r = action.apply(sdc);
            if (r instanceof byte[])
                throw new ELIBSecurityUnsafeUsageException("SDC 작업 수행에 따른 반환값이 바이트 배열입니다!");
            return r;
        }
    }

    public static void transmitZeroCopy(final SensitiveDataContainer sdc, final WritableByteChannel channel) throws ELIBSecurityProcessException {
        if (!sdc.getArena().scope().isAlive()) {
            throw new IllegalStateException("이미 소거 완료되었거나 유효하지 않은 컨테이너입니다!");
        }

        // 메소드 내부에서만 생존하는 임시 Direct ByteBuffer 뷰 생성
        // 이 객체는 절대 외부로 반환되거나 다른 스레드로 전달되어서는 안 됨
        ByteBuffer transientView = sdc.getMemorySegment().asByteBuffer();

        // WritableByteChannel (SocketChannel 등)에 기록
        // 채널이 Direct ByteBuffer를 인식하면 Java Heap으로 데이터를 복사하지 않고
        // JNI를 통해 OS의 write() 또는 send() 시스템 콜로 메모리 주소를 직접 넘김
        while (transientView.hasRemaining()) {
            try {
                channel.write(transientView);
            } catch (IOException e) {
                throw new ELIBSecurityProcessException(e);
            }
        }

        // gc hint
        transientView = null;
    }

    @Override
    public void close() {
        // 스레드 안전성과 다중 호출 시의 멱등성을 보장하기 위해 인스턴스 락 사용
        synchronized (this) {
            // 이미 닫힌 경우 early-return
            if (this.arena == null || !this.arena.scope().isAlive()) {
                log.debug("이미 소거 완료되었거나 유효하지 않은 컨테이너입니다.");
                return;
            }

            try {
                // TODO: 아래 메소드는 FFIStandard 구조체 레이아웃만 받음. 하지만 현재 sdc는 this.memorySegement 값이 해당 구조체만 들어오는게 아님. 이에따라 추가 조치 필요
                NativeProcessResult<Void> result = ConstableFactory.Std.joepOrder(this.memorySegment);
                if (result.isSuccess())
                    log.debug("'{}' 스레드 JOEP 명령 -> Rust측 소거 완료", Thread.currentThread().getName());
            } catch (ELIBSecurityProcessException e) {
                throw new ELIBSecurityCritical(e);
            } finally {
                // 소거 후 메모리 락 해제
                ConstableFactory.Std.systemCallMemoryUnlock(false, memorySegment); // TODO: 실제 OS 수정
                this.arena.close();
            }
        }
    }
}
