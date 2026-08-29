package space.qu4nt.entanglementlib.security.provider.bcfips;

import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.RandomProvider;
import space.qu4nt.entanglementlib.security.provider.SDCCodec;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/// NIST SP 800-90A HMAC-DRBG(SHA-512)를 사용하는 검증된 [RandomProvider] 구현입니다.
///
/// 플랫폼 [SecureRandom]을 엔트로피 소스로 삼아 예측 저항성(prediction resistance)을 켠 상태로
/// DRBG를 구성하므로, 매 생성 요청마다 엔트로피를 다시 공급받습니다.
///
/// # Limitation
/// 양자 네트워크(quantum network) 엔트로피 전략(값 1)은 대응 소스가 없으므로 지원하지 않습니다.
@ApiStatus.Internal
public final class BCFipsRandomProvider implements RandomProvider {

    /// RNG 엔트로피 전략 중 양자 네트워크를 의미하는 값 (RNG.QUANTUM_NETWORK와 동일)
    private static final byte QUANTUM_NETWORK = (byte) 1;

    private static final byte[] PERSONALIZATION = "space.qu4nt.entanglementlib".getBytes(StandardCharsets.UTF_8);
    private static final int NONCE_BYTES = 32;
    private static final int SECURITY_STRENGTH_BITS = 256;

    private final FipsSecureRandom drbg;

    public BCFipsRandomProvider() {
        final SecureRandom entropySource = new SecureRandom();
        // DRBG 인스턴스화 nonce는 비밀값이 아니며 BouncyCastle이 내부 보관하므로 소거하지 않는다
        final byte[] nonce = new byte[NONCE_BYTES];
        entropySource.nextBytes(nonce);

        this.drbg = FipsDRBG.SHA512_HMAC
                .fromEntropySource(entropySource, true)
                .setPersonalizationString(PERSONALIZATION)
                .setSecurityStrength(SECURITY_STRENGTH_BITS)
                .build(nonce, true);
    }

    @Override
    public SensitiveDataContainer generate(final @NotNull SDCScopeContext scope, final byte entropyStrategy, final long length)
            throws ELIBSecurityProcessException {
        if (entropyStrategy == QUANTUM_NETWORK)
            throw new ELIBSecurityProcessException("양자 네트워크 엔트로피 전략은 BouncyCastle FIPS 백엔드에서 지원하지 않습니다.");
        if (length <= 0 || length > Integer.MAX_VALUE)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 난수 길이입니다: " + length);

        byte[] buffer = null;
        try {
            buffer = new byte[(int) length];
            drbg.nextBytes(buffer);
            return SDCCodec.write(scope, buffer);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("BouncyCastle FIPS 난수 생성 중 치명적 예외가 발생했습니다!", t);
        } finally {
            SDCCodec.wipe(buffer);
        }
    }

    @Override
    public @NotNull String backendName() {
        return "BouncyCastle FIPS " + drbg.getAlgorithm() + " (SP 800-90A, 검증)";
    }
}
