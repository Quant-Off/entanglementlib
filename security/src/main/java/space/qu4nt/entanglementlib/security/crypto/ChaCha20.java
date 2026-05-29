package space.qu4nt.entanglementlib.security.crypto;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.InternalNativeBridge;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.CryptoProviders;

/// ChaCha20-Poly1305 AEAD 유틸리티입니다.
///
/// 모든 입출력은 [SensitiveDataContainer]를 통해 소유권(ownership)이 통제됩니다. 실제 연산은
/// [CryptoProviders]에 설정된 백엔드로 위임됩니다. 검증된 JDK 백엔드를 선택하면 즉시 동작하며,
/// entlib-native 백엔드는 아직 FFI에 노출되지 않아 예외를 던집니다.
///
/// @author Q. T. Felix
public final class ChaCha20 {

    private ChaCha20() {
        throw new UnsupportedOperationException("cannot access");
    }

    /// ChaCha20-Poly1305 암호화를 수행합니다.
    ///
    /// @param context   메모리 소거 생명주기를 관리하는 컨텍스트
    /// @param key       32바이트 대칭키
    /// @param nonce     12바이트 Nonce
    /// @param aad       추가 인증 데이터 (선택 사항)
    /// @param plaintext 암호화할 평문 데이터
    /// @return 암호화된 암호문(MAC 태그 포함)를 담은 SDC 객체
    public static @NotNull SensitiveDataContainer encrypt(
            final @NotNull SDCScopeContext context,
            final @NotNull SensitiveDataContainer key,
            final @NotNull SensitiveDataContainer nonce,
            final @Nullable SensitiveDataContainer aad,
            final @NotNull SensitiveDataContainer plaintext) throws ELIBSecurityProcessException {
        validate(context, key, nonce, aad, plaintext);
        return CryptoProviders.aead().encrypt(context, key, nonce, aad, plaintext);
    }

    /// ChaCha20-Poly1305 복호화를 수행합니다.
    ///
    /// @return 복호화된 평문 데이터를 담은 SDC 객체
    public static @NotNull SensitiveDataContainer decrypt(
            final @NotNull SDCScopeContext context,
            final @NotNull SensitiveDataContainer key,
            final @NotNull SensitiveDataContainer nonce,
            final @Nullable SensitiveDataContainer aad,
            final @NotNull SensitiveDataContainer ciphertext) throws ELIBSecurityProcessException {
        validate(context, key, nonce, aad, ciphertext);
        return CryptoProviders.aead().decrypt(context, key, nonce, aad, ciphertext);
    }

    private static void validate(final SDCScopeContext scope,
                                 final SensitiveDataContainer key,
                                 final SensitiveDataContainer nonce,
                                 final @Nullable SensitiveDataContainer aad,
                                 final SensitiveDataContainer data) {
        if (scope == null)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 스코프 컨텍스트입니다!");
        requireAlive(key, "키");
        requireAlive(nonce, "Nonce");
        requireAlive(data, "데이터");
        if (aad != null && !InternalNativeBridge.unwrapArena(aad).scope().isAlive())
            throw new ELIBSecurityIllegalArgumentException("이미 소거된 AAD 컨테이너입니다!");
    }

    private static void requireAlive(final SensitiveDataContainer container, final String label) {
        if (container == null || !InternalNativeBridge.unwrapArena(container).scope().isAlive())
            throw new ELIBSecurityIllegalArgumentException("유효하지 않거나 이미 소거된 " + label + " 컨테이너입니다!");
    }
}
