/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
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
