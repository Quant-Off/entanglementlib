package space.qu4nt.entanglementlib.security.provider.jdk;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.RandomProvider;

import java.security.SecureRandom;

/// JDK 표준 [SecureRandom](플랫폼 CSPRNG)을 사용하는 검증된 [RandomProvider] 구현입니다.
///
/// # Limitation
/// 양자 네트워크(quantum network) 엔트로피 전략(값 1)은 검증된 JDK 백엔드에 대응 소스가 없으므로
/// 지원하지 않습니다. 그 외 전략은 로컬 하드웨어 기반 [SecureRandom]으로 처리합니다.
@ApiStatus.Internal
public final class JdkRandomProvider implements RandomProvider {

    /// RNG 엔트로피 전략 중 양자 네트워크를 의미하는 값 (RNG.QUANTUM_NETWORK와 동일)
    private static final byte QUANTUM_NETWORK = (byte) 1;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public SensitiveDataContainer generate(final @NotNull SDCScopeContext scope, final byte entropyStrategy, final long length)
            throws ELIBSecurityProcessException {
        if (entropyStrategy == QUANTUM_NETWORK)
            throw new ELIBSecurityProcessException("양자 네트워크 엔트로피 전략은 검증된 JDK 백엔드에서 지원하지 않습니다.");
        if (length <= 0 || length > Integer.MAX_VALUE)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 난수 길이입니다: " + length);

        byte[] buffer = null;
        try {
            buffer = new byte[(int) length];
            secureRandom.nextBytes(buffer);
            return SdcCodec.write(scope, buffer);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("검증된 JDK 난수 생성 중 치명적 예외가 발생했습니다!", t);
        } finally {
            SdcCodec.wipe(buffer);
        }
    }

    @Override
    public @NotNull String backendName() {
        return "JDK SecureRandom (검증)";
    }
}
