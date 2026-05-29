/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.protocol;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.iss.exception.ISSProtocolException;

/// 전송 계층 레코드 종류입니다. 애플리케이션 명령(PING/PUT 등)은 [#DATA] 레코드의 암호화된
/// 본문 안에 별도로 인코딩되며, 와이어 관찰자에게 노출되지 않습니다.
///
/// @author Q. T. Felix
public enum Opcode {

    /// 애플리케이션 페이로드를 운반하는 레코드
    DATA((byte) 0x01),

    /// 인증된 세션 종료 레코드 (트렁케이션 공격 방어용 close_notify 대응)
    CLOSE((byte) 0x02);

    private final byte code;

    Opcode(final byte code) {
        this.code = code;
    }

    public byte code() {
        return code;
    }

    public static @NotNull Opcode from(final byte code) throws ISSProtocolException {
        return switch (code) {
            case 0x01 -> DATA;
            case 0x02 -> CLOSE;
            default -> throw new ISSProtocolException("알 수 없는 레코드 opcode 입니다");
        };
    }
}
