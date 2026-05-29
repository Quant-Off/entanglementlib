/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss;

import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.entlibnative.NativeSpecContext;
import space.qu4nt.entanglementlib.security.provider.CryptoProviderConfig;

/// 폐쇄망 내부 공유 서버(ISS)의 코드레벨 진입 파사드입니다.
///
/// 검증 전용(verified) 모드로 보안 모듈을 초기화하는 편의 메소드를 제공합니다. 이 모드는 미검증
/// 네이티브 바이너리를 로드하지 않으므로 에어갭 배포에 적합합니다. 서버는 연결 스레드 간 컨테이너
/// 공유가 필요하므로 `SHARED` arena 모드로 초기화합니다.
///
/// @author Q. T. Felix
public final class Iss {

    private Iss() {
        throw new UnsupportedOperationException("cannot access");
    }

    /// 검증 전용·SHARED arena 모드로 보안 모듈을 초기화합니다(서버·클라이언트 공통).
    ///
    /// 코어 i18n 초기화는 ISS 동작에 불필요하므로 수행하지 않습니다. ISS의 사용자 대면 문자열은
    /// 자체 한국어 문자열을 사용합니다.
    public static void initializeVerified() {
        EntanglementLibSecurityFacade.initialize(EntanglementLibSecurityConfig.create(
                NativeSpecContext.defaults(),
                HeuristicArenaFactory.ArenaMode.SHARED,
                CryptoProviderConfig.verifiedDefaults()));
    }
}
