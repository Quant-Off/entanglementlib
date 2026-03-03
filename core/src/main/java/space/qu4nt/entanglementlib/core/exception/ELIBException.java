/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.core.exception;

import java.io.Serial;

/// 얽힘 라이브러리 전반에서 사용되는 기본 예외 클래스입니다.
///
/// 이 클래스는 [Exception]을 상속받으며, 기본적으로 `Checked Exception`입니다.
/// 확장하여 다양한 상황에 대해 예외 처리가 가능합니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
public class ELIBException extends Exception {

    @Serial
    private static final long serialVersionUID = 2378593800480779310L;

    /**
     * 새로운 {@link ELIBException} 인스턴스를 생성하는 기본 생성자 메소드입니다.
     */
    public ELIBException() {
        super();
    }

    /**
     * 다국어 처리가 필요하지 않은 경우 이 인스턴스를 사용할 수 있습니다.
     *
     * @param message 메시지
     */
    public ELIBException(String message) {
        super(message);
    }

    /**
     * 발생한 예외만 넘기기 위해 이 인스턴스를 사용할 수 있습니다.
     *
     * @param cause 발생 예외
     */
    public ELIBException(Throwable cause) {
        super(cause);
    }

    /// 다국어 처리가 필요하지 않으며, 발생한 예외를 넘기기 위해 이
    /// 인스턴스를 사용할 수 있습니다.
    ///
    /// @param message 메시지
    /// @param cause   발생 예외
    public ELIBException(String message, Throwable cause) {
        super(message, cause);
    }
}
