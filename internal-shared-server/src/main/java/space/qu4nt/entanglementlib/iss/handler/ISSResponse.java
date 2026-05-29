/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.handler;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/// 핸들러가 반환하는 애플리케이션 응답입니다. 와이어 본문은 `status(1) || body(rest)` 형식으로
/// 직렬화되어 [Opcode#DATA] 레코드의 암호화 페이로드에 실립니다.
///
/// @author Q. T. Felix
public final class ISSResponse {

    private final ISSStatus status;
    private final byte[] body;

    private ISSResponse(final ISSStatus status, final byte[] body) {
        this.status = status;
        this.body = body;
    }

    public static @NotNull ISSResponse ok() {
        return new ISSResponse(ISSStatus.OK, new byte[0]);
    }

    public static @NotNull ISSResponse ok(final byte @NotNull [] body) {
        return new ISSResponse(ISSStatus.OK, body);
    }

    /// [#ok(byte[])] 별칭입니다.
    public static @NotNull ISSResponse of(final byte @NotNull [] body) {
        return new ISSResponse(ISSStatus.OK, body);
    }

    public static @NotNull ISSResponse notFound() {
        return new ISSResponse(ISSStatus.NOT_FOUND, new byte[0]);
    }

    public static @NotNull ISSResponse error(final @NotNull String message) {
        return new ISSResponse(ISSStatus.ERROR, message.getBytes(StandardCharsets.UTF_8));
    }

    public static @NotNull ISSResponse badRequest(final @NotNull String message) {
        return new ISSResponse(ISSStatus.BAD_REQUEST, message.getBytes(StandardCharsets.UTF_8));
    }

    public static @NotNull ISSResponse unknownCommand(final @NotNull String command) {
        return new ISSResponse(ISSStatus.UNKNOWN_COMMAND, command.getBytes(StandardCharsets.UTF_8));
    }

    public @NotNull ISSStatus status() {
        return status;
    }

    public byte @NotNull [] body() {
        return body;
    }

    /// 본문을 UTF-8 문자열로 해석합니다(상태 메시지·텍스트 응답용).
    public @NotNull String bodyAsText() {
        return new String(body, StandardCharsets.UTF_8);
    }

    public byte @NotNull [] encode() {
        final byte[] out = new byte[1 + body.length];
        out[0] = status.code();
        System.arraycopy(body, 0, out, 1, body.length);
        return out;
    }

    public static @NotNull ISSResponse decode(final byte @NotNull [] payload) {
        if (payload.length == 0)
            return new ISSResponse(ISSStatus.ERROR, new byte[0]);
        final ISSStatus status = ISSStatus.from(payload[0]);
        final byte[] body = Arrays.copyOfRange(payload, 1, payload.length);
        return new ISSResponse(status, body);
    }
}
