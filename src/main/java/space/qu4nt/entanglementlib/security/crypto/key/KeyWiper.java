/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.key;

import org.jetbrains.annotations.ApiStatus;
import space.qu4nt.entanglementlib.exception.secure.EntLibSensitiveDataException;

import java.util.Objects;

/**
 * 키 소거 작업을 수행하는 함수형 인터페이스입니다.
 * <p>
 * 이 인터페이스는 암호화 키를 안전하게 소거하기 위한 연산을 정의합니다.
 * {@link java.util.function.Consumer}와 유사하지만 {@link EntLibSensitiveDataException}을 던질 수 있습니다.
 *
 * @param <T> 소거할 키의 타입
 * @author Q. T. Felix
 * @since 1.1.0
 */
@ApiStatus.Obsolete
@FunctionalInterface
public interface KeyWiper<T> {

    /**
     * 전달받은 키에 대해 소거 연산을 수행하는 메소드입니다.
     * <p>
     * 연산 중 {@link EntLibSensitiveDataException} 예외가 발생할 수 있습니다.
     *
     * @param t 소거할 키 객체
     * @throws EntLibSensitiveDataException 키 소거 중 발생 가능한 예외
     */
    void accept(T t) throws EntLibSensitiveDataException;

    /**
     * 이 소거 연산 후에 추가 소거 연산을 수행하는 합성 {@link KeyWiper}를 반환하는 메소드입니다.
     *
     * @param after 이 연산 후에 수행할 소거 연산
     * @return 합성된 {@link KeyWiper}
     * @throws EntLibSensitiveDataException 키 소거 중 발생 가능한 예외
     */
    default KeyWiper<T> andThen(KeyWiper<? super T> after) throws EntLibSensitiveDataException {
        Objects.requireNonNull(after);
        return (T t) -> {
            accept(t);
            after.accept(t);
        };
    }
}
