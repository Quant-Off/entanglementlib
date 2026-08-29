/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.web;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.iss.exception.ISSException;
import space.qu4nt.entanglementlib.iss.internal.SDCBytes;
import space.qu4nt.entanglementlib.iss.transport.Kdf;
import space.qu4nt.entanglementlib.security.crypto.rng.RNG;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/// LHW 브리지 기동 시 1회 발급되는 웹 콘솔 접속 토큰입니다.
///
/// # Security Note
/// 토큰 평문은 발급 직후 터미널에 1회 출력하고 폐기합니다. 브리지는 평문 대신 SHA3-256
/// 다이제스트만 보관하며, 검증은 제시된 토큰의 다이제스트를 상수 시간 비교로 수행합니다.
/// 출력용 hex 문자열은 `heap` [String]으로 존재하는 노출면이 있으나, 운영자가 브라우저에
/// 직접 입력해야 하는 자격 증명이므로 감수하는 절충입니다.
///
/// @author Q. T. Felix
public final class LhwToken {

    private static final int TOKEN_BYTES = 32;
    private static final int TOKEN_HEX_LENGTH = TOKEN_BYTES * 2;

    private final byte[] digest;

    private LhwToken(final byte[] digest) {
        this.digest = digest;
    }

    /// 발급 결과입니다. [#tokenHex]는 터미널 출력 후 참조를 버려야 합니다.
    public record Issued(@NotNull String tokenHex, @NotNull LhwToken verifier) {
    }

    /// 하드웨어 엔트로피로 32바이트 토큰을 발급합니다.
    ///
    /// @throws ISSException 난수 생성 또는 다이제스트 계산 실패 시
    public static @NotNull Issued issue() throws ISSException {
        try (SDCScopeContext scope = new SDCScopeContext()) {
            final SensitiveDataContainer random = RNG.generateRNG(RNG.LOCAL_HARDWARE, scope, TOKEN_BYTES);
            final byte[] raw = SDCBytes.export(random);
            final String hex;
            try {
                hex = toHex(raw);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
            final byte[] digest = Kdf.sha3_256(scope, hex.getBytes(StandardCharsets.US_ASCII));
            return new Issued(hex, new LhwToken(digest));
        } catch (ELIBSecurityProcessException e) {
            throw new ISSException("접속 토큰 발급에 실패했습니다", e);
        }
    }

    /// 제시된 토큰을 상수 시간으로 검증합니다. 형식이 어긋나면 즉시 거부합니다.
    public boolean verify(final @Nullable String presented) {
        if (presented == null || presented.length() != TOKEN_HEX_LENGTH)
            return false;
        try (SDCScopeContext scope = new SDCScopeContext()) {
            final byte[] candidate = Kdf.sha3_256(scope, presented.getBytes(StandardCharsets.US_ASCII));
            return MessageDigest.isEqual(digest, candidate);
        } catch (ELIBSecurityProcessException e) {
            return false;
        }
    }

    private static String toHex(final byte[] data) {
        final StringBuilder sb = new StringBuilder(data.length * 2);
        for (final byte b : data)
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        return sb.toString();
    }
}
