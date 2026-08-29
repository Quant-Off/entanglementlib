package space.qu4nt.entanglementlib.security.provider.jdk;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.DigestProvider;
import space.qu4nt.entanglementlib.security.provider.SDCCodec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/// JDK 표준 JCA를 사용하는 검증된 [DigestProvider] 구현입니다.
///
/// SHA-2 / SHA-3 고정 길이 다이제스트를 [MessageDigest]로 계산합니다. 선택적으로 외부 JCA 공급자명
/// (예: `BC`)을 지정하면 해당 공급자를 통해 계산합니다.
///
/// # Limitation
/// SHAKE(XOF) 가변 길이 출력은 JDK 표준 [MessageDigest]가 제공하지 않으므로 이 백엔드에서 지원하지
/// 않습니다. SHAKE가 필요하면 네이티브 백엔드 또는 XOF를 지원하는 사용자 정의 공급자를 사용하세요.
@ApiStatus.Internal
public final class JdkDigestProvider implements DigestProvider {

    @Nullable
    private final String jcaProviderName;

    public JdkDigestProvider(final @Nullable String jcaProviderName) {
        this.jcaProviderName = jcaProviderName;
    }

    @Override
    public SensitiveDataContainer sha2(final @NotNull SDCScopeContext scope, final int length, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        validateLength(length, "SHA-2");
        return digest("SHA-" + length, scope, input);
    }

    @Override
    public SensitiveDataContainer sha3(final @NotNull SDCScopeContext scope, final int length, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        validateLength(length, "SHA-3");
        return digest("SHA3-" + length, scope, input);
    }

    @Override
    public SensitiveDataContainer shake(final @NotNull SDCScopeContext scope, final int variant, final long outputBytes, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        throw new ELIBSecurityProcessException(
                "SHAKE(XOF) 가변 길이 출력은 검증된 JDK 백엔드에서 지원하지 않습니다. " +
                "네이티브 백엔드 또는 XOF를 지원하는 사용자 정의 공급자를 사용하세요.");
    }

    @Override
    public @NotNull String backendName() {
        return jcaProviderName == null ? "JDK JCA (검증)" : "JDK JCA (" + jcaProviderName + ", 검증)";
    }

    private SensitiveDataContainer digest(final @NotNull String algorithm, final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        byte[] in = null;
        byte[] out = null;
        try {
            final MessageDigest md = jcaProviderName == null
                    ? MessageDigest.getInstance(algorithm)
                    : MessageDigest.getInstance(algorithm, jcaProviderName);
            in = SDCCodec.read(input);
            out = md.digest(in);
            return SDCCodec.write(scope, out);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new ELIBSecurityProcessException("검증된 JDK 백엔드에서 '" + algorithm + "' 알고리즘을 사용할 수 없습니다.", e);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("검증된 JDK 다이제스트 연산 중 치명적 예외가 발생했습니다!", t);
        } finally {
            SDCCodec.wipe(in, out);
        }
    }

    private static void validateLength(final int length, final @NotNull String family) {
        if (length != 224 && length != 256 && length != 384 && length != 512)
            throw new ELIBSecurityIllegalArgumentException("지원하지 않는 " + family + " 길이입니다: " + length);
    }
}
