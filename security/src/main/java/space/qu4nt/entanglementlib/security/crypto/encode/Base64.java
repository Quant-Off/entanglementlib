package space.qu4nt.entanglementlib.security.crypto.encode;

import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.CryptoProviders;

/// 네이티브 메모리 기반의 안전한 `Base64` 인코딩 및 디코딩 유틸리티입니다.
/// 모든 입출력은 [SensitiveDataContainer]를 통해 소유권(ownership)이 통제되며,
/// 가비지 컬렉터가 관리하는 자바 `heap` 메모리에 민감 데이터를 노출하지 않습니다.
///
/// 실제 연산은 [CryptoProviders]에 설정된 백엔드(검증된 JDK 또는 entlib-native)로 위임됩니다.
public final class Base64 {

    private Base64() {
        throw new AssertionError("cannot access");
    }

    /// 제공된 보안 컨테이너의 데이터를 Base64로 인코딩합니다.
    /// Zero-Trust 원칙에 따라 오직 `Off-Heap` 컨테이너 간의 연산만 허용합니다.
    ///
    /// # Security Note
    /// 입력 컨테이너(input)와 출력 컨테이너(output)의 생명 주기는 이 메소드를 호출한
    /// 외부의 컨텍스트 [SDCScopeContext] 또는 `try-with-resources`가 책임집니다.
    ///
    /// @param scope 데이터 상호 작용을 수행할 보안 컨테이너 스코프
    /// @param input 인코딩 타겟 컨테이너
    /// @return Base64 인코딩 결과가 담긴 새로운 보안 컨테이너
    public static SensitiveDataContainer encode(final SDCScopeContext scope, final SensitiveDataContainer input) throws ELIBSecurityProcessException {
        validate(scope, input);
        return CryptoProviders.encoding().base64Encode(scope, input);
    }

    /// `Base64`로 인코딩된 민감 데이터를 디코딩하는 메소드입니다.
    /// Zero-Trust 원칙에 따라 오직 `Off-Heap` 컨테이너 간의 연산만 허용합니다.
    ///
    /// # Security Note
    /// 입력 컨테이너(input)와 출력 컨테이너(output)의 생명 주기는 이 메소드를 호출한
    /// 외부의 컨텍스트 [SDCScopeContext] 또는 `try-with-resources`가 책임집니다.
    ///
    /// @param scope 데이터 생명주기를 통제할 스코프 컨텍스트
    /// @param input Base64로 인코딩된 데이터를 담고 있는 입력 컨테이너
    /// @return 디코딩된 원본 데이터가 담긴 새로운 보안 컨테이너 (스코프에 귀속됨)
    /// @throws ELIBSecurityProcessException 연산 실패 또는 메모리 할당 오류 시 발생
    public static SensitiveDataContainer decode(final SDCScopeContext scope, final SensitiveDataContainer input) throws ELIBSecurityProcessException {
        validate(scope, input);
        return CryptoProviders.encoding().base64Decode(scope, input);
    }

    private static void validate(final SDCScopeContext scope, final SensitiveDataContainer input) {
        if (scope == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 스코프 컨텍스트입니다!");
        if (input == null || !InternalNativeBridge.unwrapArena(input).scope().isAlive())
            throw new ELIBSecurityIllegalArgumentException("유효하지 않거나 이미 소거된 입력 컨테이너입니다!");
    }
}
