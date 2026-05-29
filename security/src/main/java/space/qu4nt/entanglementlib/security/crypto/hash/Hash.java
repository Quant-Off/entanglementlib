package space.qu4nt.entanglementlib.security.crypto.hash;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.CryptoProviders;

/// 네이티브 메모리 기반의 안전한 해시(SHA-2 / SHA-3 / SHAKE) 유틸리티입니다.
///
/// 모든 입출력은 [SensitiveDataContainer]를 통해 소유권(ownership)이 통제되며,
/// 가비지 컬렉터가 관리하는 자바 `heap` 메모리에 민감 데이터를 노출하지 않습니다.
///
/// 실제 연산은 [CryptoProviders]에 설정된 백엔드(검증된 JDK 또는 entlib-native)로 위임됩니다.
/// 입출력 컨테이너의 생명 주기는 호출자가 전달한 [SDCScopeContext]가 책임집니다.
///
/// @author Q. T. Felix
public final class Hash {

    private Hash() {
        throw new AssertionError("cannot access");
    }

    /// SHA-2 다이제스트를 계산합니다.
    ///
    /// @param length 다이제스트 비트 길이 (224, 256, 384, 512)
    /// @param scope  데이터 생명주기를 통제할 스코프 컨텍스트
    /// @param input  해시 대상 컨테이너
    /// @return 다이제스트 결과가 담긴 새로운 보안 컨테이너 (스코프에 귀속됨)
    public static SensitiveDataContainer sha2(
            final int length,
            final @NotNull SDCScopeContext scope,
            final @NotNull SensitiveDataContainer input
    ) throws ELIBSecurityProcessException {
        validate(scope, input);
        return CryptoProviders.digest().sha2(scope, length, input);
    }

    /// SHA-3 다이제스트를 계산합니다.
    ///
    /// @param length 다이제스트 비트 길이 (224, 256, 384, 512)
    /// @param scope  데이터 생명주기를 통제할 스코프 컨텍스트
    /// @param input  해시 대상 컨테이너
    /// @return 다이제스트 결과가 담긴 새로운 보안 컨테이너 (스코프에 귀속됨)
    public static SensitiveDataContainer sha3(
            final int length,
            final @NotNull SDCScopeContext scope,
            final @NotNull SensitiveDataContainer input
    ) throws ELIBSecurityProcessException {
        validate(scope, input);
        return CryptoProviders.digest().sha3(scope, length, input);
    }

    /// SHAKE 가변 길이 출력 함수(XOF)를 계산합니다.
    ///
    /// @param length     SHAKE 변형 (128 또는 256)
    /// @param byteOutLen 생성할 출력 바이트 길이
    /// @param scope      데이터 생명주기를 통제할 스코프 컨텍스트
    /// @param input      해시 대상 컨테이너
    /// @return SHAKE 출력이 담긴 새로운 보안 컨테이너 (스코프에 귀속됨)
    public static SensitiveDataContainer sha3Shake(
            final int length,
            final long byteOutLen,
            final @NotNull SDCScopeContext scope,
            final @NotNull SensitiveDataContainer input
    ) throws ELIBSecurityProcessException {
        validate(scope, input);
        return CryptoProviders.digest().shake(scope, length, byteOutLen, input);
    }

    private static void validate(final SDCScopeContext scope, final SensitiveDataContainer input) {
        if (scope == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 스코프 컨텍스트입니다!");
        if (input == null || !InternalNativeBridge.unwrapArena(input).scope().isAlive())
            throw new ELIBSecurityIllegalArgumentException("유효하지 않거나 이미 소거된 입력 컨테이너입니다!");
    }
}
