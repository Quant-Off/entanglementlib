/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.handler;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.net.InetAddress;

/// 핸들러에 전달되는 요청 컨텍스트입니다. 복호화된 명령·본문과 인증된 피어 정보를 노출합니다.
///
/// @param command 명령 이름
/// @param payload 명령별 본문(복호화된 평문)
/// @param peer    접속 피어 주소 (인메모리 채널 사용 시 `null`)
/// @author Q. T. Felix
public record ISSRequestContext(@NotNull String command, byte @NotNull [] payload, @Nullable InetAddress peer) {
}
