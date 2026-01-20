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

package space.qu4nt.entanglementlib.exception;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;

/**
 * {@code EntanglementLib}에서 발생하는 모든 예외가 확장하는 부모 클래스입니다.
 * <p>
 * 이 클래스를 상속받아 얽힘 라이브러리의 예외를 확장할 수 있습니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public class EntanglementLibException extends RuntimeException {
// TODO: Exception, RuntimeException 구분하여 체계화
    /**
     * 상세 메시지나 원인 예외 없이 새로운 {@link EntanglementLibException} 객체를 생성합니다.
     */
    public EntanglementLibException() {
        super();
    }

    /**
     * 원인 예외를 포함하여 새로운 {@link EntanglementLibException} 객체를 생성합니다.
     *
     * @param cause 발생한 원인 예외 ({@code null} 값은 원인이 존재하지 않거나 알 수 없음을 나타냄)
     */
    public EntanglementLibException(Throwable cause) {
        super(cause);
    }

    /**
     * 상세 메시지를 포함하여 새로운 {@link EntanglementLibException} 객체를 생성합니다.
     *
     * @param message 상세 예외 메시지
     */
    public EntanglementLibException(String message) {
        super(message);
    }

    /**
     * 언어 리소스 번들에서 메시지를 조회하여 새로운 {@link EntanglementLibException} 객체를 생성합니다.
     * <p>
     * 생성 시 {@link ExceptionLogger}를 통해 예외 로그가 기록됩니다.
     *
     * @param clazz   메시지 구역을 식별하기 위한 클래스 타입
     * @param fullKey 언어 파일 내의 메시지 키
     * @param <T>     메시지 구역 식별 타입
     */
    public <T> EntanglementLibException(Class<T> clazz, @NotNull String fullKey) {
        super(LanguageInstanceBased.create(clazz).msg(fullKey));
        ExceptionLogger.log(clazz, fullKey, this);
    }

    /**
     * 언어 리소스 번들에서 메시지를 조회하고, 포맷팅 인자를 적용하여 새로운 {@link EntanglementLibException} 객체를 생성합니다.
     * <p>
     * 가변 인자를 받아 메시지 내의 {@code {}} 플레이스홀더를 치환합니다.
     * 생성 시 {@link ExceptionLogger}를 통해 예외 로그가 기록됩니다.
     *
     * @param clazz   메시지 구역을 식별하기 위한 클래스 타입
     * @param fullKey 언어 파일 내의 메시지 키
     * @param args    메시지 포맷팅에 사용할 인자들
     * @param <T>     메시지 구역 식별 타입
     */
    public <T> EntanglementLibException(Class<T> clazz, @NotNull String fullKey, Object... args) {
        super(LanguageInstanceBased.create(clazz).argsNonTopKey(fullKey, args));
        ExceptionLogger.log(clazz, fullKey, this);
    }

    /**
     * 언어 리소스 번들에서 메시지를 조회하고, 원인 예외를 포함하여 새로운 {@link EntanglementLibException} 객체를 생성합니다.
     * <p>
     * 생성 시 {@link ExceptionLogger}를 통해 예외 로그가 기록됩니다.
     *
     * @param clazz   메시지 구역을 식별하기 위한 클래스 타입
     * @param fullKey 언어 파일 내의 메시지 키
     * @param cause   발생한 원인 예외
     * @param <T>     메시지 구역 식별 타입
     */
    public <T> EntanglementLibException(Class<T> clazz, @NotNull String fullKey, @NotNull Throwable cause) {
        super(LanguageInstanceBased.create(clazz).thr(fullKey, cause), cause);
        ExceptionLogger.log(clazz, fullKey, cause);
    }

    /**
     * 언어 리소스 번들에서 메시지를 조회하고, 포맷팅 인자를 적용하며 원인 예외를 포함하여 새로운 {@link EntanglementLibException} 객체를 생성합니다.
     * <p>
     * 가변 인자를 받아 메시지 내의 {@code {}} 플레이스홀더를 치환합니다.
     * 생성 시 {@link ExceptionLogger}를 통해 예외 로그가 기록됩니다.
     *
     * @param clazz   메시지 구역을 식별하기 위한 클래스 타입
     * @param fullKey 언어 파일 내의 메시지 키
     * @param cause   발생한 원인 예외
     * @param args    메시지 포맷팅에 사용할 인자들
     * @param <T>     메시지 구역 식별 타입
     */
    public <T> EntanglementLibException(Class<T> clazz, @NotNull String fullKey, @NotNull Throwable cause, Object... args) {
        super(LanguageInstanceBased.create(clazz).thr(fullKey, cause, args), cause);
        ExceptionLogger.log(clazz, fullKey, cause);
    }
}
