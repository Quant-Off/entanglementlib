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

package space.qu4nt.entanglementlib.security;

import org.bouncycastle.util.encoders.Base64;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Range;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.experimental.exception.EntLibKeyDestroyException;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * 생성 가능한 키를 래핑하는 클래스에서 구현되는 인터페이스입니다.
 * <p>
 * 암호학적 문자열을 생성하는 용도로도 사용됩니다.
 *
 * @param <T> 키 타입
 * @author Q. T. Felix
 * @since 1.1.0
 */
public interface EntLibKey<T> {

    /**
     * 키를 소거하는 메소드입니다. 키 객체의 {@code spec}을
     * 찾아 리플렉션을 통해 민감 변수를 재귀적으로 소거합니다.
     * <p>
     * 필요한 경우 콜백을 통해 특정 형식의 키를 소거할 수도 있습니다.
     * 이 콜백은 각 키 소거 로직이 모두 수행된 이후에 호출됩니다.
     *
     * @param callback 사용자 설정 키 소거 콜백
     */
    void wipe(@Nullable CustomWiper<T> callback);

    /**
     * 암호학적으로 안전한 바이트 배열을 생성하는 메소드입니다.
     *
     * @param length 0 이상의 바이트 배열 사이즈
     * @return {@code Base64} 인코딩된 문자열
     */
    static byte @NotNull [] generateSafeRandomBytes(@Range(from = 0, to = Integer.MAX_VALUE) int length) {
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
    static @NotNull String generateBase64String(@Range(from = 0, to = Integer.MAX_VALUE) int length) {
        return Base64.toBase64String(generateSafeRandomBytes(length));
    }

    @FunctionalInterface
    interface CustomWiper<T> {

        /**
         * 전달받은 키 대해 연산을 수행하는 메소드입니다.
         * 연산 중 {@link space.qu4nt.entanglementlib.exception.security.EntLibKeyDestroyException}
         * 예외가 발생할 수 있습니다.
         *
         * @param t 연산
         * @throws EntLibKeyDestroyException 연산 중 발생 가능한 예외
         */
        void accept(T t) throws EntLibKeyDestroyException;

        default CustomWiper<T> andThen(CustomWiper<? super T> after) throws EntLibKeyDestroyException {
            Objects.requireNonNull(after);
            return (T t) -> {
                accept(t);
                after.accept(t);
            };
        }
    }
}
