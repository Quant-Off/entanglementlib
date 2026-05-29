package space.qu4nt.entanglementlib.security.provider.entlibnative;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.AeadProvider;

/// `entlib-native` AEAD(ChaCha20-Poly1305) [AeadProvider] 구현입니다.
///
/// # Status
/// ChaCha20-Poly1305은 아직 `entlib-native` FFI 경계에 노출되지 않았습니다 (base64/hex/SHA-2/SHA-3만 노출됨).
/// 따라서 모든 연산은 [ELIBSecurityProcessException]을 던집니다. 검증된 AEAD가 필요하면 JDK 검증
/// 공급자를 선택하세요.
@ApiStatus.Internal
public final class EntLibNativeAeadProvider implements AeadProvider {

    private static final String NOT_EXPOSED =
            "ChaCha20-Poly1305은 아직 entlib-native FFI에 노출되지 않았습니다 (base64/hex/SHA-2/SHA-3만 노출됨)";

    @Override
    public SensitiveDataContainer encrypt(final @NotNull SDCScopeContext scope,
                                          final @NotNull SensitiveDataContainer key,
                                          final @NotNull SensitiveDataContainer nonce,
                                          final @Nullable SensitiveDataContainer aad,
                                          final @NotNull SensitiveDataContainer plaintext) throws ELIBSecurityProcessException {
        throw new ELIBSecurityProcessException(NOT_EXPOSED);
    }

    @Override
    public SensitiveDataContainer decrypt(final @NotNull SDCScopeContext scope,
                                          final @NotNull SensitiveDataContainer key,
                                          final @NotNull SensitiveDataContainer nonce,
                                          final @Nullable SensitiveDataContainer aad,
                                          final @NotNull SensitiveDataContainer ciphertext) throws ELIBSecurityProcessException {
        throw new ELIBSecurityProcessException(NOT_EXPOSED);
    }

    @Override
    public @NotNull String backendName() {
        return "entlib-native (FFI, 미노출)";
    }
}
