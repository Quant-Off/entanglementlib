package space.qu4nt.entanglementlib.security.provider;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

/// 난수(random) 생성을 제공하는 교체 가능한 공급자(provider) 계약입니다.
///
/// 생성된 난수는 [SensitiveDataContainer]에 바인딩되어 스코프 종료 시 소거(zeroize)됩니다.
public interface RandomProvider {

    /// 지정된 엔트로피 전략에 따라 난수를 생성합니다.
    ///
    /// @param scope           결과 컨테이너가 귀속될 스코프 컨텍스트
    /// @param entropyStrategy 엔트로피 전략 (로컬 하드웨어 또는 양자 네트워크)
    /// @param length          생성할 난수의 바이트 길이
    /// @return 난수 데이터를 담은 컨테이너
    SensitiveDataContainer generate(@NotNull SDCScopeContext scope, byte entropyStrategy, long length)
            throws ELIBSecurityProcessException;

    /// 이 공급자의 백엔드를 식별하는 사람이 읽을 수 있는 이름입니다.
    @NotNull String backendName();
}
