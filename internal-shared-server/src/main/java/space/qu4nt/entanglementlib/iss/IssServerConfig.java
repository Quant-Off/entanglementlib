/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.net.InetAddress;
import java.util.List;

/// [IssServer] 구성입니다. [IssServer#builder()]로 생성합니다.
///
/// @param bindHost              바인드 호스트 (기본 127.0.0.1)
/// @param port                  바인드 포트 (0이면 임의 포트)
/// @param psk                   사전 공유 키 (서버가 소유·소거하지 않음, 호출자 소유)
/// @param maxConnections        최대 동시 연결 수
/// @param handshakeTimeoutMillis 핸드셰이크 제한 시간
/// @param idleTimeoutMillis     데이터 단계 유휴 읽기 제한 시간
/// @param allowNonLoopback      비루프백 바인드 허용 여부
/// @param peerAllowlist         피어 IP 허용목록 (비어 있으면 임의 피어 허용, PSK는 별도 강제)
/// @author Q. T. Felix
public record IssServerConfig(@NotNull String bindHost,
                              int port,
                              @NotNull SensitiveDataContainer psk,
                              int maxConnections,
                              int handshakeTimeoutMillis,
                              int idleTimeoutMillis,
                              boolean allowNonLoopback,
                              @NotNull List<InetAddress> peerAllowlist) {
}
