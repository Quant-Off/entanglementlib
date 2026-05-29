/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.exception;

import space.qu4nt.entanglementlib.core.exception.ELIBException;

import java.io.Serial;

/// 폐쇄망 내부 공유 서버(ISS) 동작 중 발생하는 검사 예외의 최상위 타입입니다.
///
/// @author Q. T. Felix
public class ISSException extends ELIBException {

    @Serial
    private static final long serialVersionUID = 7_842_001_001_000_001L;

    public ISSException() {
    }

    public ISSException(final String message) {
        super(message);
    }

    public ISSException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public ISSException(final Throwable cause) {
        super(cause);
    }
}
