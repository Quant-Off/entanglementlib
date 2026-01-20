/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package space.qu4nt.entanglementlib.experimental.crypto.key;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/// 암호화 키를 네이티브 메모리에 안전하게 저장하고 관리하는 클래스입니다.
///
/// 현재 [Arena#ofConfined()]를 사용하고 있어 이 키 객체를 생성한 스레드에서만 접근 가능합니다.
/// 만약 클라이언트-서버 통신 과정에서 여러 스레드가 이 키를 공유해야 한다면
/// [Arena#ofShared()]로 변경을 고려해야 합니다.
///
/// 이 클래스는 [AutoCloseable]을 구현하여 *try-with-resources* 구문과 함께
/// 사용할 때 자동으로 키 메모리가 소거됩니다.
///
/// Rust로 작성된 `entanglement_secure_wipe` 네이티브 함수를 바인딩하여,
/// 키 소거 시 컴파일러 최적화를 방지하고 강제적인 메모리 덮어쓰기(volatile write)를 수행합니다.
///
/// 마크다운이 편하네요, 이 클래스부터 천천히 마크다운이 적용됩니다.
///
/// @author Q. T. Felix
/// @see KeyWiper
/// @since 1.1.0
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
     *
     * @return 키 바이트 배열, 또는 스레드 불일치 시 {@code null}
     */
    public byte @Nullable [] toByteArray() {
        try {
            return getKeySegment().toArray(ValueLayout.JAVA_BYTE);
        } catch (WrongThreadException e) {
            log.error("키 스레드가 일치하지 않습니다!", e);
        }
        return null;
    }

    /**
     * 키 메모리를 안전하게 소거하는 메소드입니다.
     * <p>
     * 바인딩된 러스트 네이티브 함수 {@code entanglement_secure_wipe}를 호출하여
     * 최적화 없는 강제 메모리 영소거(zeroing)를 수행합니다.
     * 네이티브 호출이 불가능한 경우 Java의 {@link MemorySegment#fill(byte)}을 사용하여 폴백합니다.
     */
    public void wipe() {
        if (arena.scope().isAlive()) {
            boolean nativeWipeSuccess = false;
            try {
                // entlib-native 함수 호출
                InternalFactory.callNativeWipeHandle().invokeExact(keySegment, keySegment.byteSize());
                nativeWipeSuccess = true;
            } catch (Throwable t) {
                log.error("네이티브 보안 소거 중 치명적 예외가 발생했습니다!", t);
            }

            // 네이티브 소거 실패 시 java레벨에서 소거
            // 근데 보통 이 경우는 확실히 문제가 있는게 맞음
            if (!nativeWipeSuccess)
                KeyDestroyHelper.zeroing(keySegment);
        }
    }

    /**
     * 키 리소스를 정리하고 메모리를 해제하는 메소드입니다.
     * <p>
     * 키 메모리를 소거한 후 {@link Arena}를 닫습니다.
     */
    @Override
    public void close() {
        wipe();
        arena.close();
    }
}