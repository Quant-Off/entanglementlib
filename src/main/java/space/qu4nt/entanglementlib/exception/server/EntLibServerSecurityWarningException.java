/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.server;

import space.qu4nt.entanglementlib.exception.EntLibException;

import java.io.Serial;

/// 이 예외는 서버의 보안 측면에서 큰 문제가 발생했거나, 시스템이 그렇게 예상할 때
/// 사용됩니다.
///
/// # Safety
///
/// 이 예외가 발생한 경우, 발생한 문제가 얽힘 라이브러리에 의해 1차적으로 막혔다는
/// 것을 의미합니다. 문제에 대해 방어되었지만, 서버의 보안 점검잉 긴급한 상황일 수
/// 있습니다.
///
/// 이 예외가 발생한다고 해서 서버가 종료되지는 않습니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
public class EntLibServerSecurityWarningException extends EntLibServerException {

    @Serial
    private static final long serialVersionUID = -9043595617089057163L;

    public EntLibServerSecurityWarningException(String type, String message) {
        super("[SERVER-SECURITY-WARNING] '" + type + "' 감지, 메시지: " + message);
    }
}
