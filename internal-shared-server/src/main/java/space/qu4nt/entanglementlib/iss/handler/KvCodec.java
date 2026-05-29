/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.handler;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.iss.exception.ISSProtocolException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/// 내장 공유 저장소 명령의 본문 인코딩 유틸입니다.
///
/// `KEY` 본문 = `keyLen(2, BE) || key(UTF-8)`
/// `KEY_VALUE` 본문 = `keyLen(2, BE) || key(UTF-8) || value(rest)`
///
/// @author Q. T. Felix
public final class KvCodec {

    private KvCodec() {
        throw new AssertionError("cannot access");
    }

    public static byte @NotNull [] encodeKey(final @NotNull String key) {
        final byte[] k = key.getBytes(StandardCharsets.UTF_8);
        validateKeyLen(k.length);
        final byte[] out = new byte[2 + k.length];
        out[0] = (byte) (k.length >>> 8);
        out[1] = (byte) k.length;
        System.arraycopy(k, 0, out, 2, k.length);
        return out;
    }

    public static byte @NotNull [] encodeKeyValue(final @NotNull String key, final byte @NotNull [] value) {
        final byte[] k = key.getBytes(StandardCharsets.UTF_8);
        validateKeyLen(k.length);
        final byte[] out = new byte[2 + k.length + value.length];
        out[0] = (byte) (k.length >>> 8);
        out[1] = (byte) k.length;
        System.arraycopy(k, 0, out, 2, k.length);
        System.arraycopy(value, 0, out, 2 + k.length, value.length);
        return out;
    }

    public static @NotNull String decodeKey(final byte @NotNull [] body) throws ISSProtocolException {
        return decodeKeyValue(body).key();
    }

    public static @NotNull KeyValue decodeKeyValue(final byte @NotNull [] body) throws ISSProtocolException {
        if (body.length < 2)
            throw new ISSProtocolException("키 길이 헤더가 없습니다");
        final int keyLen = ((body[0] & 0xFF) << 8) | (body[1] & 0xFF);
        if (2 + keyLen > body.length)
            throw new ISSProtocolException("키 길이가 본문을 초과했습니다");
        final String key = new String(body, 2, keyLen, StandardCharsets.UTF_8);
        final byte[] value = Arrays.copyOfRange(body, 2 + keyLen, body.length);
        return new KeyValue(key, value);
    }

    private static void validateKeyLen(final int len) {
        if (len == 0)
            throw new IllegalArgumentException("키가 비어 있습니다");
        if (len > 0xFFFF)
            throw new IllegalArgumentException("키가 65535바이트를 초과했습니다");
    }

    /// 디코딩된 키·값 쌍입니다.
    public record KeyValue(@NotNull String key, byte @NotNull [] value) {
    }
}
