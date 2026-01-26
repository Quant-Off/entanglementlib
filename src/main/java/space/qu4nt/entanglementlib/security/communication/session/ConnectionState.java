/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.communication.session;

public enum ConnectionState {

    /// 참여자가 TCP 연결되었지만, 핸드셰이킹을 시작하진 않았습니다.
    CONNECTING,

    /// 참여자가 핸드셰이킹합니다. 이 과정에 키 교환을 수행할 수
    /// 있습니다.
    HANDSHAKING,

    /// 참여자의 보안 터널이 활성화되었습니다.
    ESTABLISHED,

    /// 참여자가 연결을 중단하고 있습니다.
    CLOSING,

    /// 참여자의 연결이 완전히 종료되었습니다.
    CLOSED
}
