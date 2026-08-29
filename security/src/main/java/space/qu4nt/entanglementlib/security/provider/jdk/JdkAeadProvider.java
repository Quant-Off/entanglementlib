package space.qu4nt.entanglementlib.security.provider.jdk;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.AeadProvider;
import space.qu4nt.entanglementlib.security.provider.SDCCodec;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/// JDK 표준 JCA를 사용하는 검증된 ChaCha20-Poly1305 [AeadProvider] 구현입니다.
///
/// 변환 알고리즘은 `ChaCha20-Poly1305`이며 RFC 8439 AEAD 구조(암호문 뒤에 16바이트 태그 부착)를
/// 따릅니다. 선택적으로 외부 JCA 공급자명을 지정할 수 있습니다.
@ApiStatus.Internal
public final class JdkAeadProvider implements AeadProvider {

    private static final String TRANSFORMATION = "ChaCha20-Poly1305";
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;

    @Nullable
    private final String jcaProviderName;

    public JdkAeadProvider(final @Nullable String jcaProviderName) {
        this.jcaProviderName = jcaProviderName;
    }

    @Override
    public SensitiveDataContainer encrypt(final @NotNull SDCScopeContext scope,
                                          final @NotNull SensitiveDataContainer key,
                                          final @NotNull SensitiveDataContainer nonce,
                                          final @Nullable SensitiveDataContainer aad,
                                          final @NotNull SensitiveDataContainer plaintext) throws ELIBSecurityProcessException {
        return doFinal(Cipher.ENCRYPT_MODE, scope, key, nonce, aad, plaintext);
    }

    @Override
    public SensitiveDataContainer decrypt(final @NotNull SDCScopeContext scope,
                                          final @NotNull SensitiveDataContainer key,
                                          final @NotNull SensitiveDataContainer nonce,
                                          final @Nullable SensitiveDataContainer aad,
                                          final @NotNull SensitiveDataContainer ciphertext) throws ELIBSecurityProcessException {
        return doFinal(Cipher.DECRYPT_MODE, scope, key, nonce, aad, ciphertext);
    }

    @Override
    public @NotNull String backendName() {
        return jcaProviderName == null ? "JDK JCA ChaCha20-Poly1305 (검증)" : "JDK JCA ChaCha20-Poly1305 (" + jcaProviderName + ", 검증)";
    }

    private SensitiveDataContainer doFinal(final int mode,
                                           final @NotNull SDCScopeContext scope,
                                           final @NotNull SensitiveDataContainer key,
                                           final @NotNull SensitiveDataContainer nonce,
                                           final @Nullable SensitiveDataContainer aad,
                                           final @NotNull SensitiveDataContainer data) throws ELIBSecurityProcessException {
        byte[] keyBytes = null;
        byte[] nonceBytes = null;
        byte[] aadBytes = null;
        byte[] inBytes = null;
        byte[] outBytes = null;
        try {
            keyBytes = SDCCodec.read(key);
            nonceBytes = SDCCodec.read(nonce);
            if (keyBytes.length != KEY_BYTES)
                throw new ELIBSecurityIllegalArgumentException("ChaCha20-Poly1305 키는 32바이트여야 합니다 (실제: " + keyBytes.length + ")");
            if (nonceBytes.length != NONCE_BYTES)
                throw new ELIBSecurityIllegalArgumentException("ChaCha20-Poly1305 Nonce는 12바이트여야 합니다 (실제: " + nonceBytes.length + ")");

            final Cipher cipher = jcaProviderName == null
                    ? Cipher.getInstance(TRANSFORMATION)
                    : Cipher.getInstance(TRANSFORMATION, jcaProviderName);

            final SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "ChaCha20");
            final IvParameterSpec ivSpec = new IvParameterSpec(nonceBytes);
            cipher.init(mode, keySpec, ivSpec);

            if (aad != null) {
                aadBytes = SDCCodec.read(aad);
                if (aadBytes.length > 0)
                    cipher.updateAAD(aadBytes);
            }

            inBytes = SDCCodec.read(data);
            outBytes = cipher.doFinal(inBytes);
            return SDCCodec.write(scope, outBytes);
        } catch (AEADBadTagException e) {
            throw new ELIBSecurityProcessException("ChaCha20-Poly1305 인증 태그 검증에 실패했습니다 (무결성 위반 또는 잘못된 키/Nonce/AAD)!", e);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("검증된 JDK AEAD 연산 중 치명적 예외가 발생했습니다!", t);
        } finally {
            SDCCodec.wipe(keyBytes, nonceBytes, aadBytes, inBytes, outBytes);
        }
    }
}
