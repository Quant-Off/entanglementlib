/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception;

/**
 * 환경 변수를 정의하지 않았거나, 사용되는 도중 예외가 발생할 수 있습니다.
 * <p>
 * 해당 예외 클래스는 {@code i18n}을 지원하지 않습니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public class EntanglementLibEnvironmentException extends RuntimeException {

    public EntanglementLibEnvironmentException(String message) {
        super(message);
    }

    public EntanglementLibEnvironmentException(String message, Throwable cause) {
        super(message, cause);
    }

}
