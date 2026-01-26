/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.session;

import lombok.Getter;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;

import java.util.concurrent.atomic.AtomicLong;

/// 세션 참여자의 암호화 컨텍스트를 관리하는 클래스입니다.
///
/// 얽힘 라이브러리 TLS 체계는 참여자가 세션에 접속할 때 이 컨텍스트를 가지고 있다고
/// 예상합니다.
///
/// @author Q. T. Felix
/// @see Session
/// @since 1.1.0
public class ParticipantSecurityContext {

    // 합의된 세션 키
    @Getter
    private volatile SensitiveDataContainer sessionKey;

    // AEAD의 논스 및 카운터
    // 수신 카운터
    private final AtomicLong readSequence = new AtomicLong(0);
    // 송신 카운터
    private final AtomicLong writeSequence = new AtomicLong(0);

    // 연결에 사용되는 특정 스트레티지(세션 기본값과 다를 경우)
    private String negotiatedStrategy;

    // 핸드셰이크 프레그먼트에 임시 저장
    private SensitiveDataContainer peerPublicKey;

    public ParticipantSecurityContext(SensitiveDataContainer sessionKey, String negotiatedStrategy, SensitiveDataContainer peerPublicKey) {
        this.sessionKey = sessionKey;
        this.negotiatedStrategy = negotiatedStrategy;
        this.peerPublicKey = peerPublicKey;
    }

    public long getNextWriteSequence() {
        return writeSequence.getAndIncrement();
    }

    public long getNextReadSequence() {
        return readSequence.getAndIncrement();
    }
}
