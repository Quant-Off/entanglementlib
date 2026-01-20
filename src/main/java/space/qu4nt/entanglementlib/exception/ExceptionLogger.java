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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 예외 발생 시 상세 정보를 로그 파일에 기록하는 클래스입니다.
 * <p>
 * 이 클래스는 SLF4J를 사용하여 로그를 기록하며,
 * 클래스패스에 있는 {@code logback.xml} 또는 {@code logback-test.xml} 설정에 따라 동작합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
final class ExceptionLogger {

    private static final Logger logger = LoggerFactory.getLogger(ExceptionLogger.class);

    /**
     * 예외 정보를 로그에 기록합니다.
     *
     * @param throwingClass 예외가 발생한 클래스
     * @param messageKey    사용된 메시지 키
     * @param throwable     발생한 예외 객체
     */
    static <T> void log(Class<T> throwingClass, String messageKey, Throwable throwable) {
        // SLF4J의 파라미터화된 메시지 형식을 사용하여 로그를 기록
        // 마지막 인자로 Throwable을 전달하면 스택 트레이스가 자동으로 포함됨
        logger.error("{} 에서 '{}' 메시지 키를 가진 예외가 발생했습니다!",
                throwingClass.getName(),
                messageKey,
                throwable);
    }
}
