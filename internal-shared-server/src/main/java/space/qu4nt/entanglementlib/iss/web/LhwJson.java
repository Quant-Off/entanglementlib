/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.web;

import org.jetbrains.annotations.NotNull;

import java.util.Collection;

/// LHW 브리지 응답 전용 최소 JSON 직렬화기입니다.
///
/// 브리지는 JSON을 파싱하지 않고 생성만 하므로(요청 본문은 raw 바이트) 외부 JSON 라이브러리를
/// 도입하지 않습니다. RFC 8259 문자열 이스케이프만 정확히 수행합니다.
///
/// @author Q. T. Felix
public final class LhwJson {

    private LhwJson() {
        throw new AssertionError("cannot access");
    }

    /// 키-값 쌍을 JSON 객체로 직렬화합니다. 값은 [String], [Number], [Boolean]만 허용합니다.
    ///
    /// @throws IllegalArgumentException 쌍이 맞지 않거나 지원하지 않는 값 타입일 때
    public static @NotNull String object(final @NotNull Object @NotNull ... pairs) {
        if (pairs.length % 2 != 0)
            throw new IllegalArgumentException("키-값 쌍이 맞지 않습니다");
        final StringBuilder sb = new StringBuilder(64);
        sb.append('{');
        for (int i = 0; i < pairs.length; i += 2) {
            if (i > 0)
                sb.append(',');
            appendString(sb, String.valueOf(pairs[i]));
            sb.append(':');
            appendValue(sb, pairs[i + 1]);
        }
        return sb.append('}').toString();
    }

    /// 문자열 컬렉션을 JSON 배열 리터럴로 직렬화합니다(객체 값으로 끼워 넣는 용도).
    public static @NotNull String stringArray(final @NotNull Collection<String> values) {
        final StringBuilder sb = new StringBuilder(32);
        sb.append('[');
        boolean first = true;
        for (final String value : values) {
            if (!first)
                sb.append(',');
            appendString(sb, value);
            first = false;
        }
        return sb.append(']').toString();
    }

    /// [#stringArray]처럼 이미 직렬화된 JSON 조각을 값으로 표시하는 래퍼입니다.
    public record Raw(@NotNull String json) {
    }

    private static void appendValue(final StringBuilder sb, final Object value) {
        switch (value) {
            case String s -> appendString(sb, s);
            case Boolean b -> sb.append(b.booleanValue());
            case Number n -> sb.append(n);
            case Raw raw -> sb.append(raw.json());
            case null, default -> throw new IllegalArgumentException("지원하지 않는 JSON 값 타입입니다");
        }
    }

    private static void appendString(final StringBuilder sb, final String value) {
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20)
                        sb.append(String.format("\\u%04x", (int) c));
                    else
                        sb.append(c);
                }
            }
        }
        sb.append('"');
    }
}
