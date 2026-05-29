/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.exception;

import java.io.Serial;

/// 와이어 프레임 파싱, 경계 검증, 시퀀스 위반 등 프로토콜 무결성 위반 시 발생합니다.
///
/// @author Q. T. Felix
public class IssProtocolException extends IssException {

    @Serial
    private static final long serialVersionUID = 7_842_001_001_000_002L;

    public IssProtocolException(final String message) {
        super(message);
    }

    public IssProtocolException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
