/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.security;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.iss.exception.IssException;
import space.qu4nt.entanglementlib.iss.protocol.WireConstants;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/// 사전 공유 키(PSK)를 off-heap [SensitiveDataContainer]로 안전하게 적재합니다.
///
/// # Security Note
/// PSK는 평문 명령행 인자로 받지 않습니다(프로세스 목록 노출 방지). 파일(raw 바이트) 또는
/// 환경변수(hex)로만 적재하며, 최소 길이([WireConstants#MIN_PSK_LEN])와 비영(non-zero) 엔트로피를
/// 강제합니다. 적재 과정의 임시 `heap` 바이트는 즉시 소거됩니다.
///
/// 반환된 컨테이너의 소유권은 호출자에게 있습니다(try-with-resources 권장). 서버처럼 여러
/// 연결 스레드가 동일 PSK를 공유하는 경우, 보안 모듈을 `SHARED` arena 모드로 초기화해야
/// 교차 스레드 접근이 허용됩니다.
///
/// @author Q. T. Felix
public final class IssPsk {

    private IssPsk() {
        throw new AssertionError("cannot access");
    }

    /// raw 바이트 키 파일에서 PSK를 적재합니다.
    public static @NotNull SensitiveDataContainer fromFile(final @NotNull Path path) throws IssException {
        final byte[] raw;
        try {
            raw = Files.readAllBytes(path);
        } catch (IOException e) {
            throw new IssException("PSK 파일을 읽을 수 없습니다: " + path, e);
        }
        return wrap(raw);
    }

    /// 환경변수에 담긴 hex 인코딩 PSK를 적재합니다.
    public static @NotNull SensitiveDataContainer fromEnv(final @NotNull String variableName) throws IssException {
        final String value = System.getenv(variableName);
        if (value == null || value.isBlank())
            throw new IssException("환경변수가 비어 있습니다: " + variableName);
        return fromHex(value.trim());
    }

    /// hex 문자열로부터 PSK를 적재합니다.
    public static @NotNull SensitiveDataContainer fromHex(final @NotNull String hex) throws IssException {
        return wrap(decodeHex(hex));
    }

    private static @NotNull SensitiveDataContainer wrap(final byte[] raw) throws IssException {
        try {
            if (raw.length < WireConstants.MIN_PSK_LEN)
                throw new IssException("PSK 길이가 최소 요구치(" + WireConstants.MIN_PSK_LEN + "바이트) 미만입니다");
            if (isAllZero(raw))
                throw new IssException("PSK 엔트로피가 유효하지 않습니다 (전부 0)");
            return new SensitiveDataContainer(raw, true);
        } catch (ELIBSecurityProcessException e) {
            throw new IssException("PSK 컨테이너 생성에 실패했습니다", e);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static boolean isAllZero(final byte[] data) {
        int acc = 0;
        for (final byte b : data)
            acc |= b;
        return acc == 0;
    }

    private static byte @NotNull [] decodeHex(final String hex) throws IssException {
        final String clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        if ((clean.length() & 1) != 0)
            throw new IssException("hex 길이가 홀수입니다");
        final byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            final int hi = digit(clean.charAt(i * 2));
            final int lo = digit(clean.charAt(i * 2 + 1));
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static int digit(final char c) throws IssException {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new IssException("유효하지 않은 hex 문자입니다");
    }
}
