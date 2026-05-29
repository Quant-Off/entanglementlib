/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.iss.internal;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;

/// off-heap [SensitiveDataContainer]와 `heap` `byte[]` 사이를 잇는 ISS 모듈 내부 브리지입니다.
///
/// # Security Note
/// 보안 모듈은 SDC의 메모리 세그먼트 접근자를 패키지 외부에 노출하지 않습니다. 따라서 ISS는
/// 공개 API인 [SensitiveDataContainer#transmitZeroCopy]만으로 바이트를 추출합니다.
/// 추출된 `byte[]`는 `heap`에 잠시 노출되며, 이는 검증 백엔드가 JCA 연동 시 감수하는 절충과
/// 동일한 수준입니다. 암호문은 비민감 데이터이므로 추출이 안전하고, 평문 추출은 디스패치
/// 직전 짧은 노출로 제한됩니다.
///
/// @author Q. T. Felix
public final class SDCBytes {

    private SDCBytes() {
        throw new AssertionError("cannot access");
    }

    /// 컨테이너의 전체 세그먼트 바이트를 `heap` 배열로 추출합니다.
    ///
    /// [SensitiveDataContainer#transmitZeroCopy]는 세그먼트 전체를 기록하므로, 할당 크기 전부가
    /// 의미 있는 페이로드인 컨테이너에만 사용해야 합니다(예: AEAD 출력, 정확히 채운 다이제스트).
    ///
    /// @throws ELIBSecurityProcessException 컨테이너가 이미 소거되었거나 채널 기록 실패 시
    public static byte @NotNull [] export(final @NotNull SensitiveDataContainer sdc) throws ELIBSecurityProcessException {
        final ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (WritableByteChannel channel = Channels.newChannel(sink)) {
            SensitiveDataContainer.transmitZeroCopy(sdc, channel);
        } catch (IOException e) {
            throw new ELIBSecurityProcessException("컨테이너 바이트 추출 실패", e);
        }
        return sink.toByteArray();
    }
}
