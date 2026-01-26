/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.critical;

/// 얽힘 라이브러리에서 발생하는 치명적인 오류를 나타내는 클래스입니다.
///
/// 이 클래스는 [Error]를 상속받으며, 복구할 수 없는 심각한 문제가 발생했을 때 사용됩니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
public class EntLibError extends Error {

    /**
     * 새로운 {@link EntLibError} 인스턴스를 생성하는 기본 생성자 메소드입니다.
     */
    public EntLibError() {
    }

    /**
     * 지정된 상세 메시지를 사용하여 새로운 {@link EntLibError} 인스턴스를 생성하는 메소드입니다.
     *
     * @param message 상세 오류 메시지
     */
    public EntLibError(String message) {
        super(message);
    }

    /**
     * 지정된 상세 메시지와 원인 예외를 사용하여 새로운 {@link EntLibError} 인스턴스를 생성하는 메소드입니다.
     *
     * @param message 상세 오류 메시지
     * @param cause   이 오류가 발생하게 된 원인 ({@code null}이 허용됨)
     */
    public EntLibError(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * 지정된 원인 예외를 사용하여 새로운 {@link EntLibError} 인스턴스를 생성하는 메소드입니다.
     * <p>
     * 상세 메시지는 {@code cause}가 {@code null}이 아닌 경우 {@code cause.toString()}의 결과로 설정됩니다.
     * </p>
     *
     * @param cause 이 오류가 발생하게 된 원인 ({@code null}이 허용됨)
     */
    public EntLibError(Throwable cause) {
        super(cause);
    }
}
