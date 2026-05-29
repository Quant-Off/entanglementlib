/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.security;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import space.qu4nt.entanglementlib.iss.exception.IssException;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/// 제로트러스트 바인드·접속 경계 정책입니다.
///
/// 기본은 최대 격리(루프백 전용)입니다. 비루프백 주소로 바인드하거나 비루프백 피어를 수용하려면
/// 명시적 옵트인이 필요하며, 옵트인 시 경고를 남깁니다. 옵트인 후에도 모든 연결은 PSK 상호
/// 인증을 통과해야 합니다.
///
/// @author Q. T. Felix
public final class BindPolicy {

    private static final Logger log = LoggerFactory.getLogger(BindPolicy.class);

    private BindPolicy() {
        throw new AssertionError("cannot access");
    }

    /// 바인드 호스트 문자열을 주소로 해석합니다.
    public static @NotNull InetAddress resolve(final @NotNull String host) throws IssException {
        try {
            return InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            throw new IssException("바인드 주소를 해석할 수 없습니다: " + host, e);
        }
    }

    /// 바인드 주소가 정책을 충족하는지 검증합니다.
    ///
    /// @throws IssException 비루프백 주소인데 옵트인이 없을 때
    public static void validateBind(final @NotNull InetAddress address, final boolean allowNonLoopback)
            throws IssException {
        if (address.isLoopbackAddress())
            return;
        if (!allowNonLoopback)
            throw new IssException("비루프백 주소 바인드는 기본 차단됩니다 (allowNonLoopback 옵트인 필요): "
                    + address.getHostAddress());
        log.warn("비루프백 주소에 바인드합니다. 폐쇄망 격리가 약화됩니다: {}", address.getHostAddress());
    }

    /// 접속한 피어가 정책상 허용되는지 판단합니다.
    ///
    /// 허용목록이 비어 있으면 임의 피어를 허용합니다(PSK 인증은 별도로 강제됨). 허용목록이 있으면
    /// 목록에 포함된 피어만 허용합니다.
    public static boolean isPeerAllowed(final @NotNull InetAddress peer, final @NotNull List<InetAddress> allowlist) {
        if (allowlist.isEmpty())
            return true;
        for (final InetAddress allowed : allowlist) {
            if (allowed.equals(peer))
                return true;
        }
        return false;
    }
}
