/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.exception;

import java.io.Serial;

/// PSK 상호 인증 실패(Finished 불일치, 다운그레이드 시도 등) 시 발생합니다.
///
/// # Security Note
/// 네트워크 관찰자에게 어떤 검증 단계에서 실패했는지 노출하지 않도록, 외부 전파 메시지는
/// 일반화하고 상세 원인은 로컬 로깅으로만 남기는 fail-closed 원칙을 따릅니다.
///
/// @author Q. T. Felix
public class ISSAuthException extends ISSException {

    @Serial
    private static final long serialVersionUID = 7_842_001_001_000_003L;

    public ISSAuthException(final String message) {
        super(message);
    }

    public ISSAuthException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
