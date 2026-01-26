/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.entlibnative;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Range;
import space.qu4nt.entanglementlib.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.Unsafe;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;

/// `Rust`의 소유권(ownership) 개념처럼 이 클래스도 전달받은 민감 정보에 대한 소유권을 가집니다.
/// 이 클래스에 저장된 데이터는 진행중인 세션에 종속되고, 세션이 종료됨에 따라 모든 데이터가 완벽하게
/// 소거됩니다. 데이터 소거는 `entlib-native`에서 진행됩니다.
///
/// [#SensitiveDataContainer(byte\[\], boolean)] 생성자를 사용하여 전달받은 바이트 배열
/// 데이터에 대한 소유권을 이 클래스에 넘길지 결정할 수 있습니다. 논리 값이 `true`일 경우 데이터는
/// 즉시 소거됩니다.
///
/// 이 컨테이너 클래스는 연쇄적으로 사용할 수 있습니다. [#bindings] 리스트는 하위(또는 동등)에
/// 또 다른 컨테이너를 보관할 수 있도록 만들어졌습니다. 이 기능은 통신 구조에서, 세션에 연결된 각
/// 통신 상대방에게 다양한 데이터를 함께 전송해야 할 때 용이합니다.
///
/// @author Q. T. Felix
/// @see HeuristicArenaFactory
/// @since 1.1.0
@Slf4j
public class SensitiveDataContainer implements AutoCloseable {

    @Getter
    private final Arena arena;
    @Getter
    private final MemorySegment memorySegment;

    /// 사용자가 인스턴스 생성에 전달한 바이트 배열 데이터
    private byte @Nullable [] fromData;

    /// 이 인스턴스가 통신 구조에서 사용되는 경우 통신 상대방에게
    /// 네이티브 메모리 세그먼트에 저장된 데이터를 직렬화하여
    /// 전달하기 위해 사용되는 바이트 배열 값입니다.
    ///
    /// 선언 시에는 `null` 상태를 가지며, 할당 후 이 데이터에
    /// 대한 소유권은 절대적으로 이 인스턴스가 가지게 됩니다.
    private byte @Nullable [] segmentData;

    /// 민감 데이터 컨테이너에 여러 데이터 컨테이너 바인딩
    /// 동시성 이슈 해결을 위해 동기적 리스트 선언
    ///
    /// # Solved Problems
    ///
    /// *`20250126` - race conditions*
    private final List<SensitiveDataContainer> bindings = Collections.synchronizedList(new ArrayList<>());

    /// 네이티브 메모리에 전달받은 정수 값(바이트 크기) 만큼의 메모리 세그먼트를
    /// 생성하여 이 인스턴스를 생성합니다.
    ///
    /// @param allocateSIze 바이트 크기
    public SensitiveDataContainer(final int allocateSIze) {
        this.arena = HeuristicArenaFactory.intelligenceCreateArena();
        this.memorySegment = Objects.requireNonNull(arena.allocate(allocateSIze));
        this.fromData = null;
    }

    /// 원본 바이트 배열을 전달받고 네이티브 메모리에 바인딩하여 이 인스턴스를 생성합니다.
    ///
    /// 생성 시점에 전달받은 원본 바이트 배열 데이터에 대한 소유권을 이 인스턴스에 넘길지 결정할 수
    /// 있습니다. 논리 값이 `true`일 경우 데이터는 즉시 소거되고, 이는 이 인스턴스가 소유권을
    /// 가질 필요가 없다는 것을 의미합니다.
    ///
    /// @param from      네이티브 메모리에 바인딩할 원본 바이트 배열
    /// @param forceWipe 인스턴스에 소유권 이전 여부
    public SensitiveDataContainer(final byte @NotNull [] from, boolean forceWipe) {
        this.arena = HeuristicArenaFactory.intelligenceCreateArena();
        this.memorySegment = Objects.requireNonNull(arena.allocateFrom(ValueLayout.JAVA_BYTE, from));
        if (forceWipe)
            KeyDestroyHelper.zeroing(from);
        else this.fromData = from;
    }

    /// 외부에서 생성된 컨테이너를 이 인스턴스의 하위 바인딩으로 추가하는 메소드입니다
    /// 동시성 안전성을 보장하기 위해 [#bindings] 리스트에 대한 락을 획득한 후 수행됩니다.
    ///
    /// @param container 하위로 종속시킬 컨테이너
    /// @return 추가된 컨테이너
    /// @throws EntLibSecureIllegalStateException 부모 컨테이너가 이미 소거된 경우
    public SensitiveDataContainer addContainerData(SensitiveDataContainer container)
            throws EntLibSecureIllegalStateException {
        synchronized (this.bindings) {
            if (!this.arena.scope().isAlive()) {
                // 이미 부모가 죽은 상태라면 추가하려는 자식도 고아 상태가 되지 않도록 예외 던짐
                throw new EntLibSecureIllegalStateException("이미 소거된 컨테이너에는 하위 데이터를 추가할 수 없습니다!");
            }
            this.bindings.add(container);
            return container;
        }
    }

    /// 새로운 크기만큼의 컨테이너를 생성하고 하위 바인딩으로 추가하는 메소드입니다
    ///
    /// @param allocateSIze 할당할 바이트 크기
    /// @return 생성 및 바인딩된 새 컨테이너
    public SensitiveDataContainer addContainerData(final int allocateSIze)
            throws EntLibSecureIllegalStateException {
        synchronized (this.bindings) {
            if (!this.arena.scope().isAlive()) {
                throw new EntLibSecureIllegalStateException("이미 소거된 컨테이너입니다!");
            }
            // lock 내부에서 생성 및 추가를 수행하여 원자성 보장
            SensitiveDataContainer s = new SensitiveDataContainer(allocateSIze);
            this.bindings.add(s);
            return s;
        }
    }

    /// 바이트 배열을 기반으로 컨테이너를 생성하고 하위 바인딩으로 추가하는 메소드입니다
    ///
    /// @param from      원본 바이트 배열
    /// @param forceWipe 원본 배열 소거 여부
    /// @return 생성 및 바인딩된 새 컨테이너
    public SensitiveDataContainer addContainerData(final byte @NotNull [] from, boolean forceWipe)
            throws EntLibSecureIllegalStateException {
        synchronized (this.bindings) {
            if (!this.arena.scope().isAlive()) {
                KeyDestroyHelper.zeroing(from);
                throw new EntLibSecureIllegalStateException("이미 소거된 컨테이너입니다! 이 예외가 발생했지만, 전달받은 바이트 배열은 소거되었습니다.");
            }
            SensitiveDataContainer s = new SensitiveDataContainer(from, forceWipe);
            this.bindings.add(s);
            return s;
        }
    }

    public Optional<SensitiveDataContainer> get(final int index) {
        try {
            return Optional.of(this.bindings.get(index));
        } catch (ArrayIndexOutOfBoundsException e) {
            log.error("인덱스 '{}'에 바인딩된 컨테이너가 없습니다!", index);
        }
        return Optional.empty();
    }

    /// 네이티브 메모리 세그먼트의 내용을 `heap` 메모리로 복사하는
    /// 메소드입니다.
    ///
    /// 복사된 데이터에 대한 소유권은 여전히 이 인스턴스가
    /// 가집니다. 인스턴스가 `try-with-resource` 블럭 내에서
    /// 사용될 경우 해당 값은 자동으로 소거됩니다.
    ///
    /// 이 메소드를 수행하면 [#segmentData] 변수를 통해
    /// 복사된 바이트 배열 데이터를 호출할 수 있습니다.
    ///
    /// # Unsafe
    ///
    /// 얽힘 라이브러리는 극한의 보안 환경을 중요시합니다. 이런 관점에서
    /// 해당 메소드는 다음의 딜레마에 빠지게 됩니다.
    ///
    /// > *어째서 안전한 `Off-Heap` 데이터를 다시 불안정한 `Java Heap`으로 복사하는가?*
    ///
    /// 이 메소드는 분명 편의성을 위한 기능이지만, Java Heap에 올라간 데이터는 GC가
    /// 동작하면서 메모리 위치를 옮길(Relocation) 수 있고, 이 과정에서 지워지지
    /// 않는 고아 복사본이 메모리 어딘가에 남을 수 있습니다.
    ///
    /// 따라서 얽힘 라이브러리의 보안 철학에 따라 이 메소드는 [`Unsafe`][Unsafe]
    /// 처리되며, 다음 릴리즈 공개 전에 제거하기로 결정했습니다.
    ///
    /// @see #getSegmentData() 복사 반환 메소드
    /// @see #getSegmentDataBase64() Base64 복사 반환 메소드
    /// @see #getSegmentDataToByteBuffer() ByteBuffer 복사 반환 메소드
    @Unsafe
    @Deprecated(forRemoval = true)
    public void exportData()
            throws EntLibSecureIllegalStateException {
        synchronized (this.bindings) {
            // 락 획득 후 생존 여부 확인 (check-then-act 보호)
            if (!arena.scope().isAlive()) {
                throw new EntLibSecureIllegalStateException("이미 소거된 컨테이너입니다!");
            }
            // 안전하게 데이터 복사
            this.segmentData = memorySegment.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /// `heap` 메모리에 복사된 데이터를 외부에서도 소거할 수 있도록 하는
    /// 메소드입니다.
    public void zeroingExportedData() {
        if (segmentData != null)
            KeyDestroyHelper.zeroing(segmentData);
    }

    /// `heap` 메모리에 복사된 네이티브 메모리 세그먼트 데이터의 복사본을
    /// 반환하는 메소드입니다.
    ///
    /// @return 네이티브 메모리 세그먼트 데이터의 바이트 배열 복사본
    public byte @Nullable [] getSegmentData() {
        return segmentData != null ? Arrays.copyOf(segmentData, segmentData.length) : null;
    }

    /// `heap` 메모리에 복사된 네이티브 메모리 세그먼트 데이터의 복사본을
    /// `Base64` 인코딩하여 반환하는 메소드입니다. 이 메소드는
    /// 직렬화에 용이합니다.
    ///
    /// 단순히 인코딩된 이 값을 직렬화할 수도 있지만, 보안상 추가적인
    /// 작업이 권장됩니다. 예를 들어, 이 값에 대칭키 암호화 연산을 수행할
    /// 수 있습니다.
    ///
    /// @return 직렬화된 네이티브 메모리 세그먼트 데이터의 바이트 배열 복사본
    public @Nullable String getSegmentDataBase64() {
        return getSegmentData() != null ? Base64.toBase64String(getSegmentData()) : null;
    }

    public ByteBuffer getSegmentDataToByteBuffer() {
        return memorySegment.asByteBuffer();
    }

    /// 인스턴스가 소유권을 가진 상태인 경우 해당 메소드를 사용하여 데이터의 복사본을 호출할 수
    /// 있습니다. 내부적으로 [Arrays#copyOf(byte\[\], int)]를 사용하여 사본을 반환합니다.
    ///
    /// @return 안전한 데이터 복사본
    public byte @Nullable [] getFromData() {
        return fromData != null ? Arrays.copyOf(fromData, fromData.length) : null;
    }

    /**
     * 암호학적으로 안전한 바이트 배열을 생성하는 메소드입니다.
     *
     * @param length 0 이상의 바이트 배열 사이즈
     * @return {@code Base64} 인코딩된 문자열
     */
    public static byte @NotNull [] generateSafeRandomBytes(@Range(from = 0, to = Integer.MAX_VALUE) int length) {
        final SecureRandom random = InternalFactory.getSafeRandom();
        final byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * 암호학적으로 안전한 {@code Base64} 인코딩된 문자열을 반환하는 메소드입니다.
     *
     * @param length 0 이상의 바이트 배열 사이즈
     * @return {@code Base64} 인코딩된 문자열
     */
    public static @NotNull String generateBase64String(@Range(from = 0, to = Integer.MAX_VALUE) int length) {
        return Base64.toBase64String(generateSafeRandomBytes(length));
    }

    @Override
    public void close() {
        // SECURE UPDATE: 20250126 - qtfelix
        // [Phase 1] 스냅샷 생성 및 연결 해제 (Critical Section 최소화)
        List<SensitiveDataContainer> snapshot;
        synchronized (bindings) {
            // 이미 닫힌 경우 빠른 종료 (Idempotency)
            if (!arena.scope().isAlive()) {
                log.warn("해당 스레드에서 이미 닫힌 컨테이너입니다.");
                return;
            }

            if (bindings.isEmpty()) {
                snapshot = Collections.emptyList();
            } else {
                // 방어적 복사: 리스트를 복제하고 원본은 즉시 비움
                snapshot = new ArrayList<>(bindings);
                bindings.clear();
            }
        } // 1차 락 해제: 이제 다른 스레드가 bindings에 접근해도 데드락이 발생하지 않음

        // [Phase 2] 하위 컨테이너 리소스 해제 (Open Call)
        // 락 바깥에서 수행하므로 자식 컨테이너가 부모를 다시 호출해도 안전함
        if (!snapshot.isEmpty()) {
            for (int i = snapshot.size() - 1; i >= 0; i--) {
                SensitiveDataContainer child = snapshot.get(i);
                try {
                    child.close();
                } catch (Exception e) {
                    log.error("하위 컨테이너 리소스 해제 중 예외가 발생했습니다!", e);
                }
            }
        }

        // [Phase 3] 네이티브 메모리 소거 및 최종 종료
        // 다시 락을 획득하여 [Phase 2] 도중에 추가된 데이터가 없는지 확인하고 소거
        synchronized (bindings) {
            // [Edge Case 방어] Phase 2 진행 중에 addContainerData가 호출되어
            // bindings에 새 데이터가 들어왔을 수 있음. 이를 확인하고 소거해야 함.
            if (!bindings.isEmpty()) {
                for (SensitiveDataContainer straggler : bindings) {
                    try {
                        straggler.close();
                    } catch (Exception e) {
                        log.error("지연 추가된 하위 컨테이너 해제 중 오류 발생", e);
                    }
                }
                bindings.clear();
            }

            // Arena가 여전히 살아있는지 확인 후 소거 (Double Check)
            if (arena.scope().isAlive()) {
                try {
                    // Rust Native Wipe 호출
                    InternalFactory.callNativeLib()
                            .getHandle("entanglement_secure_wipe")
                            .invokeExact(memorySegment, memorySegment.byteSize());
                } catch (Throwable e) {
                    log.error("치명적 보안 예외가 발생했습니다! (Native Wipe Failed)", e);
                }

                // Java Heap 데이터 소거
                if (fromData != null) {
                    KeyDestroyHelper.zeroing(fromData);
                    fromData = null; // GC Hint
                }
                zeroingExportedData();
                segmentData = null; // GC Hint

                // Arena 종료
                arena.close();
            }
        }
    }
}
