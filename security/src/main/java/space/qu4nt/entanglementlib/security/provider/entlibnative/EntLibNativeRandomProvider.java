package space.qu4nt.entanglementlib.security.provider.entlibnative;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.RandomProvider;

/// `entlib-native` 난수 생성 [RandomProvider] 구현입니다.
///
/// # Status
/// 난수 생성기는 아직 `entlib-native` FFI 경계에 노출되지 않았습니다 (base64/hex/SHA-2/SHA-3만 노출됨).
/// 따라서 [#generate]는 [ELIBSecurityProcessException]을 던집니다. 검증된 난수가 필요하면 JDK 검증
/// 공급자를 선택하세요.
@ApiStatus.Internal
public final class EntLibNativeRandomProvider implements RandomProvider {

    private static final String NOT_EXPOSED =
            "RNG는 아직 entlib-native FFI에 노출되지 않았습니다 (base64/hex/SHA-2/SHA-3만 노출됨)";

    @Override
    public SensitiveDataContainer generate(final @NotNull SDCScopeContext scope, final byte entropyStrategy, final long length)
            throws ELIBSecurityProcessException {
        throw new ELIBSecurityProcessException(NOT_EXPOSED);
    }

    @Override
    public @NotNull String backendName() {
        return "entlib-native (FFI, 미노출)";
    }
}
