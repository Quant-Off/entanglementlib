package space.qu4nt.entanglementlib.security.provider.bcfips;

import org.bouncycastle.crypto.OutputDigestCalculator;
import org.bouncycastle.crypto.OutputXOFCalculator;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.DigestProvider;
import space.qu4nt.entanglementlib.security.provider.SDCCodec;

/// BouncyCastle FIPS 경량 API를 사용하는 검증된 [DigestProvider] 구현입니다.
///
/// SHA-2 / SHA-3 고정 길이 다이제스트는 [FipsSHS.OperatorFactory]로, SHAKE 가변 길이 출력(XOF)은
/// [FipsSHS.XOFOperatorFactory]로 계산합니다. JCA `Provider` 전역 등록을 하지 않으므로 JVM 전역
/// 상태에 영향을 주지 않습니다.
///
/// # Note
/// SHA-2·SHA-3·SHAKE는 모두 FIPS 승인 알고리즘이므로 `approved-only` 모드에서도 동작합니다.
@ApiStatus.Internal
public final class BCFipsDigestProvider implements DigestProvider {

    private final FipsSHS.OperatorFactory<FipsSHS.Parameters> digestFactory = new FipsSHS.OperatorFactory<>();
    private final FipsSHS.XOFOperatorFactory<FipsSHS.Parameters> xofFactory = new FipsSHS.XOFOperatorFactory<>();

    @Override
    public SensitiveDataContainer sha2(final @NotNull SDCScopeContext scope, final int length, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        return digest(sha2Parameters(length), "SHA-" + length, scope, input);
    }

    @Override
    public SensitiveDataContainer sha3(final @NotNull SDCScopeContext scope, final int length, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        return digest(sha3Parameters(length), "SHA3-" + length, scope, input);
    }

    @Override
    public SensitiveDataContainer shake(final @NotNull SDCScopeContext scope, final int variant, final long outputBytes, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        final FipsSHS.Parameters parameters = shakeParameters(variant);
        if (outputBytes <= 0 || outputBytes > Integer.MAX_VALUE)
            throw new ELIBSecurityIllegalArgumentException("유효하지 않은 SHAKE 출력 길이입니다: " + outputBytes);

        byte[] in = null;
        byte[] out = null;
        try {
            in = SDCCodec.read(input);
            final OutputXOFCalculator<FipsSHS.Parameters> calculator = xofFactory.createOutputXOFCalculator(parameters);
            calculator.getFunctionStream().update(in, 0, in.length);
            out = calculator.getFunctionOutput((int) outputBytes);
            return SDCCodec.write(scope, out);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("BouncyCastle FIPS SHAKE 연산 중 치명적 예외가 발생했습니다!", t);
        } finally {
            SDCCodec.wipe(in, out);
        }
    }

    @Override
    public @NotNull String backendName() {
        return "BouncyCastle FIPS SHS (검증)";
    }

    private SensitiveDataContainer digest(final @NotNull FipsSHS.Parameters parameters,
                                          final @NotNull String algorithm,
                                          final @NotNull SDCScopeContext scope,
                                          final @NotNull SensitiveDataContainer input) throws ELIBSecurityProcessException {
        byte[] in = null;
        byte[] out = null;
        try {
            in = SDCCodec.read(input);
            final OutputDigestCalculator<FipsSHS.Parameters> calculator = digestFactory.createOutputDigestCalculator(parameters);
            calculator.getDigestStream().update(in, 0, in.length);
            out = calculator.getDigest();
            return SDCCodec.write(scope, out);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (Throwable t) {
            throw new ELIBSecurityProcessException("BouncyCastle FIPS '" + algorithm + "' 다이제스트 연산 중 치명적 예외가 발생했습니다!", t);
        } finally {
            SDCCodec.wipe(in, out);
        }
    }

    private static FipsSHS.Parameters sha2Parameters(final int length) {
        return switch (length) {
            case 224 -> FipsSHS.SHA224;
            case 256 -> FipsSHS.SHA256;
            case 384 -> FipsSHS.SHA384;
            case 512 -> FipsSHS.SHA512;
            default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHA-2 길이입니다: " + length);
        };
    }

    private static FipsSHS.Parameters sha3Parameters(final int length) {
        return switch (length) {
            case 224 -> FipsSHS.SHA3_224;
            case 256 -> FipsSHS.SHA3_256;
            case 384 -> FipsSHS.SHA3_384;
            case 512 -> FipsSHS.SHA3_512;
            default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHA-3 길이입니다: " + length);
        };
    }

    private static FipsSHS.Parameters shakeParameters(final int variant) {
        return switch (variant) {
            case 128 -> FipsSHS.SHAKE128;
            case 256 -> FipsSHS.SHAKE256;
            default -> throw new ELIBSecurityIllegalArgumentException("지원하지 않는 SHAKE 변형입니다: " + variant);
        };
    }
}
