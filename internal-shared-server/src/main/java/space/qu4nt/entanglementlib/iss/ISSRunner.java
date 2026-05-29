/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss;

import space.qu4nt.entanglementlib.iss.cli.ISSCLI;

/// 폐쇄망 내부 공유 서버(ISS) 실행 진입점입니다. 명령행 처리는 [ISSCLI]에 위임합니다.
///
/// @author Q. T. Felix
public final class ISSRunner {

    private ISSRunner() {
        throw new UnsupportedOperationException("cannot access");
    }

    public static void main(final String[] args) {
        ISSCLI.main(args);
    }
}
