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

import space.qu4nt.entanglementlib.experimental.exception.EntLibKeyDestroyException;

import java.util.Objects;

/**
 * 키 소거 작업을 수행하는 함수형 인터페이스입니다.
 * <p>
 * 이 인터페이스는 암호화 키를 안전하게 소거하기 위한 연산을 정의합니다.
 * {@link java.util.function.Consumer}와 유사하지만 {@link EntLibKeyDestroyException}을 던질 수 있습니다.
 *
 * @param <T> 소거할 키의 타입
 * @author Q. T. Felix
 * @see EntLibCryptoKey
 * @since 1.1.0
 */
@FunctionalInterface
public interface KeyWiper<T> {

    /**
     * 전달받은 키에 대해 소거 연산을 수행하는 메소드입니다.
     * <p>
     * 연산 중 {@link EntLibKeyDestroyException} 예외가 발생할 수 있습니다.
     *
     * @param t 소거할 키 객체
     * @throws EntLibKeyDestroyException 키 소거 중 발생 가능한 예외
     */
    void accept(T t) throws EntLibKeyDestroyException;

    /**
     * 이 소거 연산 후에 추가 소거 연산을 수행하는 합성 {@link KeyWiper}를 반환하는 메소드입니다.
     *
     * @param after 이 연산 후에 수행할 소거 연산
     * @return 합성된 {@link KeyWiper}
     * @throws EntLibKeyDestroyException 키 소거 중 발생 가능한 예외
     */
    default KeyWiper<T> andThen(KeyWiper<? super T> after) throws EntLibKeyDestroyException {
        Objects.requireNonNull(after);
        return (T t) -> {
            accept(t);
            after.accept(t);
        };
    }
}
