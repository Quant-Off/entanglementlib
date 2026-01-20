/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.key;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/**
 * 암호화 키를 네이티브 메모리에 안전하게 저장하고 관리하는 클래스입니다.
 * <p>
 * 현재 {@link Arena#ofConfined()}를 사용하고 있어 이 키 객체를 생성한 스레드에서만 접근 가능합니다.
 * 만약 클라이언트-서버 통신 과정에서 여러 스레드가 이 키를 공유해야 한다면
 * {@link Arena#ofShared()}로 변경을 고려해야 합니다.
 * </p>
 * <p>
 * 이 클래스는 {@link AutoCloseable}을 구현하여 try-with-resources 구문과 함께
 * 사용할 때 자동으로 키 메모리가 소거됩니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see KeyWiper
 */
@Slf4j
public class EntLibCryptoKey implements AutoCloseable {

    /**
     * 네이티브 메모리 관리를 위한 {@link Arena} 인스턴스입니다.
     */
    private final Arena arena;

    /**
     * 키 데이터가 저장된 네이티브 메모리 세그먼트입니다.
     */
    private final MemorySegment keySegment;

    /**
     * 원시 키 바이트 배열로부터 {@link EntLibCryptoKey} 인스턴스를 생성하는 생성자입니다.
     * <p>
     * 생성 시 원본 키 데이터는 네이티브 메모리로 복사된 후 즉시 소거됩니다.
     * </p>
     *
     * @param rawKey 원시 키 바이트 배열
     */
    public EntLibCryptoKey(byte[] rawKey) {
        // 현재 스레드에서만 접근 가능한 메모리 세션 오픈
        this.arena = Arena.ofConfined();
        // Native 영역에 메모리 할당
        this.keySegment = this.arena.allocate(rawKey.length);

        // rawKey를 힙 세그먼트로 래핑하여 네이티브 메모리로 복사
        MemorySegment sourceSegment = MemorySegment.ofArray(rawKey);
        MemorySegment.copy(sourceSegment, 0, this.keySegment, 0, rawKey.length);

        // rawKey 복사 후 즉시 원본 rawKey 소거
        KeyDestroyHelper.zeroing(rawKey);
    }

    /**
     * 키가 저장된 네이티브 메모리 세그먼트를 반환하는 메소드입니다.
     *
     * @return 키 데이터가 저장된 {@link MemorySegment}
     * @throws IllegalStateException 키 세그먼트가 이미 닫힌 경우
     */
    public MemorySegment getKeySegment() {
        if (!arena.scope().isAlive())
            throw new IllegalStateException("Key segment is already closed.");
        return keySegment;
    }

    /**
     * 키 데이터를 바이트 배열로 변환하여 반환하는 메소드입니다.
     * <p>
     * 반환된 바이트 배열은 힙 메모리에 복사되므로 사용 후 반드시 소거해야 합니다.
     * </p>
     *
     * @return 키 바이트 배열, 또는 스레드 불일치 시 {@code null}
     */
    public byte @Nullable [] toByteArray() {
        try {
            return getKeySegment().toArray(ValueLayout.JAVA_BYTE);
        } catch (WrongThreadException e) {
            log.error("키 thread 불일치", e);
        }
        return null;
    }

    /**
     * 키 메모리를 0으로 덮어써서 소거하는 메소드입니다.
     * <p>
     * 이 메소드는 키가 더 이상 필요하지 않을 때 보안을 위해 호출됩니다.
     * </p>
     */
    public void wipe() {
        if (arena.scope().isAlive()) {
            keySegment.fill((byte) 0);
        }
    }

    /**
     * 키 리소스를 정리하고 메모리를 해제하는 메소드입니다.
     * <p>
     * 키 메모리를 소거한 후 {@link Arena}를 닫습니다.
     * </p>
     */
    @Override
    public void close() {
        wipe();
        arena.close();
    }
}
