package space.qu4nt.entanglementlib.security.provider;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

/// 다이제스트(SHA-2 / SHA-3 / SHAKE) 연산을 제공하는 교체 가능한 공급자(provider) 계약입니다.
///
/// 구현체는 입력 [SensitiveDataContainer]를 소비하여 결과를 담은 새로운 컨테이너를 [SDCScopeContext]에
/// 할당하여 반환합니다. 입출력 컨테이너의 생명주기는 호출자가 전달한 스코프가 책임집니다.
public interface DigestProvider {

    /// SHA-2 다이제스트를 계산합니다.
    ///
    /// @param scope  결과 컨테이너가 귀속될 스코프 컨텍스트
    /// @param length 다이제스트 비트 길이 (224, 256, 384, 512)
    /// @param input  해시 타겟 컨테이너
    /// @return 다이제스트 결과 컨테이너
    SensitiveDataContainer sha2(@NotNull SDCScopeContext scope, int length, @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException;

    /// SHA-3 다이제스트를 계산합니다.
    ///
    /// @param scope  결과 컨테이너가 귀속될 스코프 컨텍스트
    /// @param length 다이제스트 비트 길이 (224, 256, 384, 512)
    /// @param input  해시 타겟 컨테이너
    /// @return 다이제스트 결과 컨테이너
    SensitiveDataContainer sha3(@NotNull SDCScopeContext scope, int length, @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException;

    /// SHAKE 가변 길이 출력 함수(XOF)를 계산합니다.
    ///
    /// @param scope       결과 컨테이너가 귀속될 스코프 컨텍스트
    /// @param variant     SHAKE 변형 (128 또는 256)
    /// @param outputBytes 생성할 출력 바이트 길이
    /// @param input       해시 타겟 컨테이너
    /// @return SHAKE 출력 컨테이너
    SensitiveDataContainer shake(@NotNull SDCScopeContext scope, int variant, long outputBytes, @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException;

    /// 이 공급자의 백엔드를 식별하는 사람이 읽을 수 있는 이름입니다.
    @NotNull String backendName();
}
