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
/// @since 1.1.0
/// @see HeuristicArenaFactory
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
    /// # Safety
    ///
    /// 이 리스트에 [Collections#synchronizedList(List)]를 사용했으나, 개별 컨테이너의
    /// [#close()]와 [#exportData()] 호출이 멀티 스레드 환경에서 겹칠 경우 `Arena`의
    /// 생명주기와 관련된 경합 조건(race condition) 문제가 발생할 수 있음을 확인했습니다.
    /// 이는 `1.1.0-Alpha`에서 을 면밀히 테스트되며, 이후 변경 소요가 있습니다.
    ///
    /// 곧바로, 이 기능을 테스트하기 위해 `JUnit5` 테스트를 작성중입니다.
    ///
    /// @version 20260126 - 발견
    @SuppressWarnings("JavadocDeclaration")
    @Unsafe
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

    public SensitiveDataContainer addContainerData(SensitiveDataContainer container) {
        this.bindings.add(container);
        return container;
    }

    public SensitiveDataContainer addContainerData(final int allocateSIze) {
        SensitiveDataContainer s = new SensitiveDataContainer(allocateSIze);
        this.bindings.add(s);
        return s;
    }

    public SensitiveDataContainer addContainerData(final byte @NotNull [] from, boolean forceWipe) {
        SensitiveDataContainer s = new SensitiveDataContainer(from, forceWipe);
        this.bindings.add(s);
        return s;
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
    /// 이러한 이유로 인해 `SDC`는 기본적으로 이 메소드를 `Unsafe`로 나타내기로
    /// 결정했습니다.
    ///
    /// @see #getSegmentData() 복사 반환 메소드
    /// @see #getSegmentDataBase64() Base64 복사 반환 메소드
    /// @see #getSegmentDataToByteBuffer() ByteBuffer 복사 반환 메소드
    @Unsafe
    public void exportData()
            throws EntLibSecureIllegalStateException {
        if (!arena.scope().isAlive())
            throw new EntLibSecureIllegalStateException("이미 소거된 컨테이너입니다!");
        this.segmentData = memorySegment.toArray(ValueLayout.JAVA_BYTE);
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
        // 안전을 위한 역순 소거
        if (!bindings.isEmpty()) {
            for (int i = bindings.size() - 1; i >= 0; i--) {
                SensitiveDataContainer child = bindings.get(i);
                try {
                    child.close();
                } catch (Exception e) {
                    log.error("하위 컨테이너 리소스 해제 중 예외가 발생했습니다!", e);
                }
            }
            bindings.clear();
        }

        if (arena.scope().isAlive()) {
            try {
                InternalFactory.callNativeLib()
                        .getHandle("entanglement_secure_wipe")
                        .invokeExact(memorySegment, memorySegment.byteSize());
            } catch (Throwable e) {
                log.error("치명적 보안 예외가 발생했습니다!", e);
            }
        }
        if (fromData != null) {
            KeyDestroyHelper.zeroing(fromData);
            fromData = null; // GC 콜
        }
        zeroingExportedData();
        segmentData = null; // GC 콜
        arena.close();
    }
}
