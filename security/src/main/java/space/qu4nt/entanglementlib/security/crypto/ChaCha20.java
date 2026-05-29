package space.qu4nt.entanglementlib.security.crypto;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

/// ChaCha20-Poly1305 AEAD 유틸리티입니다.
///
/// # Status
/// 이 알고리즘은 아직 `entlib-native` FFI 경계에 노출되지 않았습니다. 현재 노출된 원샷 FFI
/// 함수는 base64 / hex / SHA-2 / SHA-3(SHAKE)뿐입니다. 따라서 모든 연산은
/// [ELIBSecurityProcessException]을 던지며, 공개 API 형태(시그니처)만 유지합니다.
///
/// 네이티브 측에서 `ffi_chacha20_poly1305_encrypt` 등 대응 함수가 노출되면 [Hash]와 동일한
/// 원샷 패턴(입력/출력 [SensitiveDataContainer]를 FFIStandard로 전달)으로 구현합니다.
///
/// @author Q. T. Felix
public final class ChaCha20 {

    private static final String NOT_EXPOSED =
            "ChaCha20-Poly1305은 아직 entlib-native FFI에 노출되지 않았습니다 (base64/hex/SHA-2/SHA-3만 노출됨)";

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
    /// @return 암호화된 사이퍼텍스트(MAC 태그 포함)를 담은 SDC 객체
    /// @throws ELIBSecurityProcessException 네이티브 FFI 미노출로 항상 발생
    public static @NotNull SensitiveDataContainer encrypt(
            final @NotNull SDCScopeContext context,
            final @NotNull SensitiveDataContainer key,
            final @NotNull SensitiveDataContainer nonce,
            final @Nullable SensitiveDataContainer aad,
            final @NotNull SensitiveDataContainer plaintext) throws ELIBSecurityProcessException {
        throw new ELIBSecurityProcessException(NOT_EXPOSED);
    }

    /// ChaCha20-Poly1305 복호화를 수행합니다.
    ///
    /// @return 복호화된 평문 데이터를 담은 SDC 객체
    /// @throws ELIBSecurityProcessException 네이티브 FFI 미노출로 항상 발생
    public static @NotNull SensitiveDataContainer decrypt(
            final @NotNull SDCScopeContext context,
            final @NotNull SensitiveDataContainer key,
            final @NotNull SensitiveDataContainer nonce,
            final @Nullable SensitiveDataContainer aad,
            final @NotNull SensitiveDataContainer ciphertext) throws ELIBSecurityProcessException {
        throw new ELIBSecurityProcessException(NOT_EXPOSED);
    }
}
