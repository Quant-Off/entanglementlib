package space.qu4nt.entanglementlib.security.provider;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;

/// AEAD(ChaCha20-Poly1305) 암호화 및 복호화를 제공하는 교체 가능한 공급자(provider) 계약입니다.
///
/// 암호문는 `암호문 || 16바이트 인증 태그` 형식으로 직렬화됩니다. 복호화는 동일 형식의 입력을
/// 기대합니다.
public interface AeadProvider {

    /// AEAD 암호화를 수행합니다.
    ///
    /// @param scope     결과 컨테이너가 귀속될 스코프 컨텍스트
    /// @param key       32바이트 대칭키
    /// @param nonce     12바이트 Nonce
    /// @param aad       추가 인증 데이터 (선택 사항)
    /// @param plaintext 암호화할 평문
    /// @return `암호문 || 태그`를 담은 결과 컨테이너
    SensitiveDataContainer encrypt(@NotNull SDCScopeContext scope,
                                   @NotNull SensitiveDataContainer key,
                                   @NotNull SensitiveDataContainer nonce,
                                   @Nullable SensitiveDataContainer aad,
                                   @NotNull SensitiveDataContainer plaintext) throws ELIBSecurityProcessException;

    /// AEAD 복호화를 수행합니다.
    ///
    /// @param scope      결과 컨테이너가 귀속될 스코프 컨텍스트
    /// @param key        32바이트 대칭키
    /// @param nonce      12바이트 Nonce
    /// @param aad        추가 인증 데이터 (선택 사항)
    /// @param ciphertext `암호문 || 태그` 형식의 입력
    /// @return 복호화된 평문 컨테이너
    SensitiveDataContainer decrypt(@NotNull SDCScopeContext scope,
                                   @NotNull SensitiveDataContainer key,
                                   @NotNull SensitiveDataContainer nonce,
                                   @Nullable SensitiveDataContainer aad,
                                   @NotNull SensitiveDataContainer ciphertext) throws ELIBSecurityProcessException;

    /// 이 공급자의 백엔드를 식별하는 사람이 읽을 수 있는 이름입니다.
    @NotNull String backendName();
}
