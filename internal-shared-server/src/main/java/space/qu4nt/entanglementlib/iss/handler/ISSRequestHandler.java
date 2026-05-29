/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.handler;

import org.jetbrains.annotations.NotNull;

/// 코드레벨 사용자가 등록하는 명령 처리기입니다.
///
/// 핸들러는 동시에 여러 연결 스레드에서 호출될 수 있으므로 스레드 안전하게 구현해야 합니다.
/// 핸들러가 던지는 예외는 서버가 포착하여 일반화된 오류 응답으로 변환합니다(fail-closed).
///
/// @author Q. T. Felix
@FunctionalInterface
public interface ISSRequestHandler {

    @NotNull ISSResponse handle(@NotNull ISSRequestContext context) throws Exception;
}
