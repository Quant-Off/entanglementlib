/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.transport;

import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.util.Arrays;

/// 핸드셰이크 결과로 확립된 방향별 세션 키 자료입니다.
///
/// 대칭키([#keyTx], [#keyRx])는 연결 스코프가 소유하는 off-heap 컨테이너이며, IV는 비밀성이
/// 요구되지 않는 nonce 솔트이므로 `byte[]`로 보관합니다(ChaCha20-Poly1305는 nonce의 유일성만
/// 요구). 연결 종료 시 IV는 [#wipe]로 소거됩니다.
///
/// @author Q. T. Felix
final class SessionKeys {

    final SensitiveDataContainer keyTx;
    final SensitiveDataContainer keyRx;
    final byte[] ivTx;
    final byte[] ivRx;

    SessionKeys(final SensitiveDataContainer keyTx,
                final SensitiveDataContainer keyRx,
                final byte[] ivTx,
                final byte[] ivRx) {
        this.keyTx = keyTx;
        this.keyRx = keyRx;
        this.ivTx = ivTx;
        this.ivRx = ivRx;
    }

    void wipe() {
        Arrays.fill(ivTx, (byte) 0);
        Arrays.fill(ivRx, (byte) 0);
    }
}
