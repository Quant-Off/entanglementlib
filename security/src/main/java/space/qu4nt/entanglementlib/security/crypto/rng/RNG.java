package space.qu4nt.entanglementlib.security.crypto.rng;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.CryptoProviders;

/// 하드웨어 진난수 및 양자 난수(quantum random number) 생성 인터페이스입니다.
/// 모든 반환 데이터는 스코프 내에서 완벽한 데이터 소거(zeroize)가 보장됩니다.
///
/// 실제 연산은 [CryptoProviders]에 설정된 백엔드로 위임됩니다. 검증된 JDK 백엔드는 로컬 하드웨어
/// 기반 SecureRandom으로 동작하며(양자 네트워크 전략은 미지원), entlib-native 백엔드는 아직 FFI에
/// 노출되지 않아 예외를 던집니다.
///
/// @author Q. T. Felix
public final class RNG {

    public static final byte LOCAL_HARDWARE = (byte) 0;
    public static final byte QUANTUM_NETWORK = (byte) 1;

    private RNG() {
        throw new UnsupportedOperationException("cannot access");
    }

    /// 지정된 엔트로피 전략(entropy strategy)에 따라 난수를 생성하고 컨테이너에 바인딩합니다.
    ///
    /// @param entropyStrategy 난수 생성 전략 (로컬 하드웨어 또는 양자 네트워크)
    /// @param scope           보안 데이터 생명주기를 관리하는 컨텍스트(context)
    /// @param length          생성할 난수의 바이트 길이
    /// @return `heap` 오염 없이 난수 데이터를 소유하는 민감 데이터 컨테이너
    public static SensitiveDataContainer generateRNG(final byte entropyStrategy,
                                                     final @NotNull SDCScopeContext scope,
                                                     final long length) throws ELIBSecurityProcessException {
        if (scope == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 스코프 컨텍스트입니다!");
        return CryptoProviders.random().generate(scope, entropyStrategy, length);
    }
}
