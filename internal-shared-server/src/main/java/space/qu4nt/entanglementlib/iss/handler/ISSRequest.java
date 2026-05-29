/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.handler;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.iss.exception.ISSProtocolException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/// 애플리케이션 요청입니다. 와이어 본문은 `cmdLen(1) || command(UTF-8) || body(rest)` 형식으로
/// 직렬화되어 암호화 페이로드에 실립니다. 명령 이름은 평문 헤더가 아닌 암호화 본문 안에 있으므로
/// 와이어 관찰자에게 노출되지 않습니다.
///
/// @param command 명령 이름 (최대 255바이트 UTF-8)
/// @param body    명령별 본문
/// @author Q. T. Felix
public record ISSRequest(@NotNull String command, byte @NotNull [] body) {

    public byte @NotNull [] encode() {
        final byte[] cmd = command.getBytes(StandardCharsets.UTF_8);
        if (cmd.length > 255)
            throw new IllegalArgumentException("명령 이름이 255바이트를 초과했습니다");
        final byte[] out = new byte[1 + cmd.length + body.length];
        out[0] = (byte) cmd.length;
        System.arraycopy(cmd, 0, out, 1, cmd.length);
        System.arraycopy(body, 0, out, 1 + cmd.length, body.length);
        return out;
    }

    public static @NotNull ISSRequest decode(final byte @NotNull [] payload) throws ISSProtocolException {
        if (payload.length < 1)
            throw new ISSProtocolException("요청 페이로드가 비어 있습니다");
        final int cmdLen = payload[0] & 0xFF;
        if (1 + cmdLen > payload.length)
            throw new ISSProtocolException("명령 이름 길이가 페이로드를 초과했습니다");
        final String command = new String(payload, 1, cmdLen, StandardCharsets.UTF_8);
        final byte[] body = Arrays.copyOfRange(payload, 1 + cmdLen, payload.length);
        return new ISSRequest(command, body);
    }
}
