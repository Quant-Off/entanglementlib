/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;

/**
 * {@code EntanglementLib}에서 발생하는 모든 예외가 확장하는 부모 클래스입니다.
 * <p>
 * {@link RuntimeException}을 상속받아 JVM(Java Virtual Machine)의 정상적인
 * 작동 중에 발생할 수 있는 예외를 발생시킵니다.
 * <p>
 * 이 클래스를 상속받아 얽힘 라이브러리의 예외를 확장할 수 있습니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public class EntanglementLibException extends RuntimeException {

    /**
     * 전달받은 예외 메시지를 사용하여 예외를 발생시킵니다.
     *
     * @param message 예외 메시지
     */
    public EntanglementLibException(String message) {
        super(message);
    }

    /**
     * 언어 파일의 특정 키를 받아 메시지를 출력합니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     * @param <T>     메시지 구역 식별 타입
     */
    public <T> EntanglementLibException(Class<T> clazz, @NotNull String fullKey) {
        super(LanguageInstanceBased.create(clazz).msg(fullKey));
        ExceptionLogger.log(clazz, fullKey, this);
    }

    /**
     * 언어 파일의 특정 키를 받아 메시지를 출력합니다.
     * 가변 변수를 받아 {@code {}} 플레이스홀더를 변수로 처리합니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     * @param args    플레이스홀더 변경 인자
     * @param <T>     메시지 구역 식별 타입
     */
    public <T> EntanglementLibException(Class<T> clazz, @NotNull String fullKey, Object... args) {
        super(LanguageInstanceBased.create(clazz).argsNonTopKey(fullKey, args));
        ExceptionLogger.log(clazz, fullKey, this);
    }

    /**
     * 언어 파일의 특정 키를 받아 예외와 함께 메시지를 출력합니다.
     * 예외 정보가 포함되어야 하는 경우에 사용됩니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     * @param cause   발생한 예외
     * @param <T>     메시지 구역 식별 타입
     */
    public <T> EntanglementLibException(Class<T> clazz, @NotNull String fullKey, @NotNull Throwable cause) {
        super(LanguageInstanceBased.create(clazz).thr(fullKey, cause), cause);
        ExceptionLogger.log(clazz, fullKey, cause);
    }

    /**
     * 언어 파일의 특정 키를 받아 예외와 함께 메시지를 출력합니다. 예외 정보가 포함되어야 하는 경우에 사용되며,
     * 가변 변수를 받아 {@code {}} 플레이스홀더를 변수로 처리합니다.
     * <p>
     * 클래스 매개변수는 메시지 구역을 식별하기 위한 키입니다.
     *
     * @param clazz   메시지 구역 식별 클래스
     * @param fullKey 메시지 키
     * @param cause   발생한 예외
     * @param args    플레이스홀더 변경 인자
     * @param <T>     메시지 구역 식별 타입
     */
    public <T> EntanglementLibException(Class<T> clazz, @NotNull String fullKey, @NotNull Throwable cause, Object... args) {
        super(LanguageInstanceBased.create(clazz).thr(fullKey, cause, args), cause);
        ExceptionLogger.log(clazz, fullKey, cause);
    }
}
