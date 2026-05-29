package space.qu4nt.entanglementlib.security.crypto.rng;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

/// 하드웨어 진난수 및 양자 난수(quantum random number) 생성 인터페이스입니다.
/// 모든 반환 데이터는 네이티브 스코프 내에서 완벽한 데이터 소거(zeroize)가 보장됩니다.
///
/// # Status
/// 난수 생성기는 아직 `entlib-native` FFI 경계에 노출되지 않았습니다. 현재 노출된 원샷 FFI
/// 함수는 base64 / hex / SHA-2 / SHA-3(SHAKE)뿐입니다. 따라서 [#generateRNG]은
/// [ELIBSecurityProcessException]을 던지며, 공개 API 형태(시그니처)만 유지합니다.
///
/// @author Q. T. Felix
public final class RNG {

    public static final byte LOCAL_HARDWARE = (byte) 0;
    public static final byte QUANTUM_NETWORK = (byte) 1;

    private static final String NOT_EXPOSED =
            "RNG는 아직 entlib-native FFI에 노출되지 않았습니다 (base64/hex/SHA-2/SHA-3만 노출됨)";

    private RNG() {
        throw new UnsupportedOperationException("cannot access");
    }

    /// 지정된 엔트로피 전략(entropy strategy)에 따라 난수를 생성하고 컨테이너에 바인딩합니다.
    ///
    /// @param entropyStrategy 난수 생성 전략 (로컬 하드웨어 또는 양자 네트워크)
    /// @param scope           보안 데이터 생명주기를 관리하는 컨텍스트(context)
    /// @param length          생성할 난수의 바이트 길이
    /// @return `heap` 오염 없이 난수 데이터를 소유하는 민감 데이터 컨테이너
    /// @throws ELIBSecurityProcessException 네이티브 FFI 미노출로 항상 발생
    public static SensitiveDataContainer generateRNG(final byte entropyStrategy,
                                                     final @NotNull SDCScopeContext scope,
                                                     final long length) throws ELIBSecurityProcessException {
        throw new ELIBSecurityProcessException(NOT_EXPOSED);
    }
}
