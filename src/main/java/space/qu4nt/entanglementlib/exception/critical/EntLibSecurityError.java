/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.exception.critical;

import java.io.Serial;

/// 이 에러는 보안 측면에서 큰 문제가 발생했거나, 시스템이 그렇게 예상할 때
/// 사용됩니다.
///
/// # Safety
///
/// 이 에러가 발생한 경우 단순히 넘어가면 절대 안 됩니다. 얽힘 라이브러리의
/// 시스템은 체계적이며, 치명적 에러를 던졌다 함은 단순히 내부적인 오류이기
/// 보단 제3자의 의한 악의적인 수행일 수 있음을 의미합니다.
///
/// @author Q. T. Felix
/// @since 1.1.0
public class EntLibSecurityError extends EntLibError {

    @Serial
    private static final long serialVersionUID = -8998597327015285852L;

    private int[] codes;

    public EntLibSecurityError(String message) {
        // secure level 상승
        // JCA/JCE 공급자 전환
        super(message);
    }
}
