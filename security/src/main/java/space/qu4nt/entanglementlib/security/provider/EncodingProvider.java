package space.qu4nt.entanglementlib.security.provider;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

/// Base64 / Hex 인코딩 및 디코딩을 제공하는 교체 가능한 공급자(provider) 계약입니다.
///
/// 구현체는 입력 [SensitiveDataContainer]를 소비하여 결과를 담은 새로운 컨테이너를 [SDCScopeContext]에
/// 할당하여 반환합니다. 입출력 컨테이너의 생명주기는 호출자가 전달한 스코프가 책임집니다.
public interface EncodingProvider {

    /// 입력 데이터를 Base64로 인코딩합니다.
    SensitiveDataContainer base64Encode(@NotNull SDCScopeContext scope, @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException;

    /// Base64 데이터를 디코딩합니다.
    SensitiveDataContainer base64Decode(@NotNull SDCScopeContext scope, @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException;

    /// 입력 데이터를 Hex로 인코딩합니다.
    SensitiveDataContainer hexEncode(@NotNull SDCScopeContext scope, @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException;

    /// Hex 데이터를 디코딩합니다.
    SensitiveDataContainer hexDecode(@NotNull SDCScopeContext scope, @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException;

    /// 이 공급자의 백엔드를 식별하는 사람이 읽을 수 있는 이름입니다.
    @NotNull String backendName();
}
