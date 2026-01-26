/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util;

import space.qu4nt.entanglementlib.exception.util.EntLibUtilityIllegalArgumentException;

import java.util.Objects;
import java.util.UUID;

public final class StringUtil {

    // Singleton
    private StringUtil() {
        throw new UnsupportedOperationException("Singleton");
    }

    /**
     * 문자열에서 특정 문자열을 다른 문자열로 치환합니다.
     *
     * @param source 원본 문자열
     * @param os     치환할 문자열(원본 문자열에서 찾을 대상)
     * @param ns     치환할 새로운 문자열
     * @return 치환된 결과 문자열, 원본 문자열이 {@code null}인 경우 {@code null}
     */
    public static String replace(String source, String os, String ns) {
        if (source == null) return null;
        int i = 0;
        if ((i = source.indexOf(os, i)) >= 0) {
            char[] sourceArray = source.toCharArray();
            char[] nsArray = ns.toCharArray();
            int oLength = os.length();
            StringBuilder buf = new StringBuilder(sourceArray.length);
            buf.append(sourceArray, 0, i).append(nsArray);
            i += oLength;
            int j = i;
            // oldString의 나머지 모든 인스턴스를 newString으로 치환
            while ((i = source.indexOf(os, i)) > 0) {
                buf.append(sourceArray, j, i - j).append(nsArray);
                i += oLength;
                j = i;
            }
            buf.append(sourceArray, j, sourceArray.length - j);
            source = buf.toString();
            buf.setLength(0);
        }
        return source;
    }

    /**
     * 문자열에서 여러 쌍의 치환 규칙에 따라 치환을 수행합니다.
     *
     * @param source 원본 문자열
     * @param rep    치환 규칙이 포함된 가변 인자 배열 (짝수 개여야 함: {치환 대상, 대체 문자열})
     * @return 치환된 결과 문자열, 원본 문자열이 {@code null}인 경우 {@code null}
     * @throws IllegalArgumentException 치환 규칙의 개수가 홀수인 경우
     */
    public static String replace(String source, String... rep) {
        if (source == null)
            return null;
        if (rep.length % 2 != 0)
            throw new EntLibUtilityIllegalArgumentException(StringUtil.class, "replace-arg-not-even-exc");
        for (int i = 0; i < rep.length; i += 2)
            source = replace(source, rep[i], rep[i + 1]);
        return source;
    }

    /**
     * 두 개의 치환 규칙을 사용하여 문자열을 치환합니다.
     *
     * @param source 원본 문자열
     * @param os1    첫 번째 치환할 문자열
     * @param ns1    첫 번째 치환할 새로운 문자열
     * @param os2    두 번째 치환할 문자열
     * @param ns2    두 번째 치환할 새로운 문자열
     * @return 두 규칙에 따라 치환된 결과 문자열
     */
    public static String replace(String source, String os1, String ns1, String os2, String ns2) {
        return replace(replace(source, os1, ns1), os2, ns2);
    }

    /**
     * 세 개의 치환 규칙을 사용하여 문자열을 치환합니다.
     *
     * @param source 원본 문자열
     * @param os1    첫 번째 치환할 문자열
     * @param ns1    첫 번째 치환할 새로운 문자열
     * @param os2    두 번째 치환할 문자열
     * @param ns2    두 번째 치환할 새로운 문자열
     * @param os3    세 번째 치환할 문자열
     * @param ns3    세 번째 치환할 새로운 문자열
     * @return 세 규칙에 따라 치환된 결과 문자열
     */
    public static String replace(String source, String os1, String ns1, String os2, String ns2, String os3, String ns3) {
        return replace(replace(replace(source, os1, ns1), os2, ns2), os3, ns3);
    }

    /**
     * 네 개의 치환 규칙을 사용하여 문자열을 치환합니다.
     *
     * @param source 원본 문자열
     * @param os1    첫 번째 치환할 문자열
     * @param ns1    첫 번째 치환할 새로운 문자열
     * @param os2    두 번째 치환할 문자열
     * @param ns2    두 번째 치환할 새로운 문자열
     * @param os3    세 번째 치환할 문자열
     * @param ns3    세 번째 치환할 새로운 문자열
     * @param os4    네 번째 치환할 문자열
     * @param ns4    네 번째 치환할 새로운 문자열
     * @return 네 규칙에 따라 치환된 결과 문자열
     */
    public static String replace(String source, String os1, String ns1, String os2, String ns2, String os3, String ns3, String os4, String ns4) {
        return replace(replace(replace(replace(source, os1, ns1), os2, ns2), os3, ns3), os4, ns4);
    }

    /**
     * 다섯 개의 치환 규칙을 사용하여 문자열을 치환합니다.
     *
     * @param source 원본 문자열
     * @param os1    첫 번째 치환할 문자열
     * @param ns1    첫 번째 치환할 새로운 문자열
     * @param os2    두 번째 치환할 문자열
     * @param ns2    두 번째 치환할 새로운 문자열
     * @param os3    세 번째 치환할 문자열
     * @param ns3    세 번째 치환할 새로운 문자열
     * @param os4    네 번째 치환할 문자열
     * @param ns4    네 번째 치환할 새로운 문자열
     * @param os5    다섯 번째 치환할 문자열
     * @param ns5    다섯 번째 치환할 새로운 문자열
     * @return 다섯 규칙에 따라 치환된 결과 문자열
     */
    public static String replace(String source, String os1, String ns1, String os2, String ns2, String os3, String ns3, String os4, String ns4, String os5, String ns5) {
        return replace(replace(replace(replace(replace(source, os1, ns1), os2, ns2), os3, ns3), os4, ns4), os5, ns5);
    }

    /**
     * 여섯 개의 치환 규칙을 사용하여 문자열을 치환합니다.
     *
     * @param source 원본 문자열
     * @param os1    첫 번째 치환할 문자열
     * @param ns1    첫 번째 치환할 새로운 문자열
     * @param os2    두 번째 치환할 문자열
     * @param ns2    두 번째 치환할 새로운 문자열
     * @param os3    세 번째 치환할 문자열
     * @param ns3    세 번째 치환할 새로운 문자열
     * @param os4    네 번째 치환할 문자열
     * @param ns4    네 번째 치환할 새로운 문자열
     * @param os5    다섯 번째 치환할 문자열
     * @param ns5    다섯 번째 치환할 새로운 문자열
     * @param os6    여섯 번째 치환할 문자열
     * @param ns6    여섯 번째 치환할 새로운 문자열
     * @return 여섯 규칙에 따라 치환된 결과 문자열
     */
    public static String replace(String source, String os1, String ns1, String os2, String ns2, String os3, String ns3, String os4, String ns4, String os5, String ns5, String os6, String ns6) {
        return replace(replace(replace(replace(replace(replace(source, os1, ns1), os2, ns2), os3, ns3), os4, ns4), os5, ns5), os6, ns6);
    }

    /**
     * 플레이스홀더 {@code {}}가 포함된 템플릿 문자열에 가변 인자를 순서대로 주입하는 메소드입니다.
     *
     * @param template 플레이스홀더 포함 문자열
     * @param args     주입할 Object 가변 인자
     * @return 주입된 결과 문자열
     * @throws NullPointerException template이 {@code null}인 경우
     */
    public static String placeholderFormat(String template, Object... args) {
        Objects.requireNonNull(template);

        StringBuilder sb = new StringBuilder(template.length() + (args.length * 10)); // 초기 용량 추정으로 메모리 재할당 최소화
        int index = 0; // 현재 탐색 위치
        int argIndex = 0; // args 인덱스

        while (true) {
            int placeholderStart = template.indexOf("{}", index);
            if (placeholderStart == -1) {
                // 남은 부분 추가
                sb.append(template.substring(index));
                break;
            }

            // 플레이스홀더 전 부분 추가
            sb.append(template, index, placeholderStart);

            // args에서 값 주입
            if (argIndex < args.length) {
                Object arg = args[argIndex++];
                sb.append(arg != null ? arg.toString() : "null");
            } else {
                // args 부족 시 "{}" 그대로 유지 (안전 처리)
                sb.append("{}");
            }

            // 다음 위치로 이동
            index = placeholderStart + 2;
        }

        // args가 남아도 무시 (요구사항 미지정 시 안전하게)
        return sb.toString();
    }

    /**
     * 바이트 배열을 문자열로 변환하는 메소드입니다.
     *
     * @param bytes        바이트 배열
     * @param addDelimiter 구분자 ","를 추가할지 여부
     * @return 변환된 문자열 ({@code null} 입력 시 {@code null} 반환)
     */
    public static String bytesToString(byte[] bytes, boolean addDelimiter) {
        if (bytes == null) {
            return null;
        }
        if (bytes.length == 0) {
            return "";
        }

        // 대용량 배열을 위해 초기 capacity 추정
        StringBuilder sb = new StringBuilder(bytes.length * (addDelimiter ? 5 : 4));

        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && addDelimiter) {
                sb.append(",");
            }
            sb.append(bytes[i]);
        }

        return sb.toString();
    }

    /**
     * 긴 문자열의 중간을 {@code ...}으로 생략하는 메소드입니다.
     *
     * @param input        입력 문자열
     * @param maxLength    생략을 적용할 최대 길이 (지정된 길이 이상이면 생략)
     * @param prefixLength 처음 부분에 보여줄 문자 수
     * @param suffixLength 끝 부분에 보여줄 문자 수
     * @return 생략된 문자열 또는 원본
     */
    public static String truncateMiddle(String input, int maxLength, int prefixLength, int suffixLength) {
        if (input == null) {
            return "";
        }
        if (maxLength <= 0 || prefixLength < 0 || suffixLength < 0)
            throw new EntLibUtilityIllegalArgumentException(StringUtil.class, "truncate-length-exc");

        int inputLength = input.length();
        if (inputLength <= maxLength) {
            return input;
        }

        // prefix + suffix + 3("...")이 maxLength를 초과하면 자동 조정
        int ellipsisLength = 3;
        int totalReserved = prefixLength + suffixLength + ellipsisLength;
        if (totalReserved > maxLength) {
            // 비율적으로 줄임 (간단히 반으로 나누기 예시)
            prefixLength = (maxLength - ellipsisLength) / 2;
            suffixLength = maxLength - ellipsisLength - prefixLength;
        }

        // 실제 추출 범위 조정 (prefix/suffix가 입력 길이 초과하지 않도록)
        int actualPrefix = Math.min(prefixLength, inputLength);
        int actualSuffix = Math.min(suffixLength, inputLength - actualPrefix);

        return input.substring(0, actualPrefix) +
                "..." +
                input.substring(inputLength - actualSuffix);
    }

    public static String truncateMiddle(String input, int prefixLength, int suffixLength) {
        return truncateMiddle(input, 100, prefixLength, suffixLength);
    }

    /**
     * {@link UUID} 타입을 바이트 배열로 변환하는 메소드입니다.
     *
     * @param uuid 타겟 {@code UUID}
     * @return 결과 바이트 배열
     */
    public static byte[] uuidToBytes(final UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        byte[] bytes = new byte[16];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (msb >>> (7 - i) * 8);
            bytes[8 + i] = (byte) (lsb >>> (7 - i) * 8);
        }
        return bytes;
    }

    /**
     * A locale independent version of toUpperCase.
     *
     * @param string input to be converted
     * @return a US Ascii uppercase version
     */
    public static String toUpperCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();
        for (int i = 0; i != chars.length; i++) {
            char ch = chars[i];
            if ('a' <= ch && 'z' >= ch) {
                changed = true;
                chars[i] = (char) (ch - 'a' + 'A');
            }
        }
        if (changed)
            return new String(chars);
        return string;
    }

    /**
     * A locale independent version of toLowerCase.
     *
     * @param string input to be converted
     * @return a US ASCII lowercase version
     */
    public static String toLowerCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();
        for (int i = 0; i != chars.length; i++) {
            char ch = chars[i];
            if ('A' <= ch && 'Z' >= ch) {
                changed = true;
                chars[i] = (char) (ch - 'A' + 'a');
            }
        }
        if (changed)
            return new String(chars);

        return string;
    }
}
