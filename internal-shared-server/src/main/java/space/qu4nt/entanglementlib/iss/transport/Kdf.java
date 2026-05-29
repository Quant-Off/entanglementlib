/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.transport;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.iss.internal.SdcBytes;
import space.qu4nt.entanglementlib.security.crypto.hash.Hash;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.nio.charset.StandardCharsets;

/// SHA3-256 스펀지 구조에 기반한 키 유도 함수(KDF)입니다.
///
/// # Security Note
/// HKDF/HMAC가 노출되지 않으므로, Keccak(SHA-3)의 길이 확장 내성을 활용한 접두 MAC
/// `SHA3-256(secret || data)`를 PRF로 사용합니다. 모든 입력 필드는 고정폭으로 정규화되어
/// 연접 모호성을 제거하며, 출력은 항상 32바이트입니다. SHAKE(XOF)는 검증 백엔드에서
/// 미지원이므로 사용하지 않습니다.
///
/// 실제 해시는 [Hash#sha3]를 통해 [space.qu4nt.entanglementlib.security.provider.CryptoProviders]에
/// 설정된 백엔드로 위임됩니다. 따라서 추후 네이티브 백엔드 활성화 시 KDF도 동일하게 전환됩니다.
///
/// @author Q. T. Felix
public final class Kdf {

    private Kdf() {
        throw new AssertionError("cannot access");
    }

    /// 전달된 조각들을 순서대로 연접한 입력에 대해 SHA3-256을 계산하여 32바이트 다이제스트를
    /// 반환합니다. 연접 임시 배열은 스코프 컨테이너 바인딩 시 즉시 소거됩니다.
    ///
    /// 주의: 입력 조각 배열 자체는 이 메소드가 소거하지 않습니다. 비밀 조각을 넘긴 호출자는
    /// 사용 후 직접 소거해야 합니다.
    ///
    /// @throws ELIBSecurityProcessException 해시 연산 또는 컨테이너 처리 실패 시
    public static byte @NotNull [] sha3_256(final @NotNull SDCScopeContext scope, final byte @NotNull []... parts)
            throws ELIBSecurityProcessException {
        final byte[] concat = concat(parts);
        final SensitiveDataContainer input = scope.allocate(concat, true);
        final SensitiveDataContainer digest = Hash.sha3(256, scope, input);
        return SdcBytes.export(digest);
    }

    /// 라벨 문자열을 US-ASCII 바이트로 변환합니다(도메인 분리 라벨 전용).
    public static byte @NotNull [] label(final @NotNull String label) {
        return label.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte @NotNull [] concat(final byte @NotNull []... parts) {
        int total = 0;
        for (final byte[] part : parts)
            total += part.length;

        final byte[] out = new byte[total];
        int offset = 0;
        for (final byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }
}
