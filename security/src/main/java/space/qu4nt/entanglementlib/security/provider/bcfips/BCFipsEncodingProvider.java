package space.qu4nt.entanglementlib.security.provider.bcfips;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.EncodingProvider;
import space.qu4nt.entanglementlib.security.provider.SDCCodec;

/// BouncyCastle FIPS 배포판에 포함된 인코더를 사용하는 [EncodingProvider] 구현입니다.
///
/// Base64는 [Base64], Hex는 [Hex](소문자)를 사용하며 JDK 백엔드와 동일한 출력을 냅니다.
///
/// # Note
/// 인코딩은 암호 연산이 아니므로 FIPS 승인 대상이 아닙니다. 백엔드 일관성을 위해 제공합니다.
@ApiStatus.Internal
public final class BCFipsEncodingProvider implements EncodingProvider {

    @Override
    public SensitiveDataContainer base64Encode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        byte[] in = null;
        byte[] out = null;
        try {
            in = SDCCodec.read(input);
            out = Base64.encode(in);
            return SDCCodec.write(scope, out);
        } finally {
            SDCCodec.wipe(in, out);
        }
    }

    @Override
    public SensitiveDataContainer base64Decode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        byte[] in = null;
        byte[] out = null;
        try {
            in = SDCCodec.read(input);
            out = Base64.decode(in);
            return SDCCodec.write(scope, out);
        } catch (ELIBSecurityProcessException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new ELIBSecurityProcessException("유효하지 않은 Base64 입력입니다!", e);
        } finally {
            SDCCodec.wipe(in, out);
        }
    }

    @Override
    public SensitiveDataContainer hexEncode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        byte[] in = null;
        byte[] out = null;
        try {
            in = SDCCodec.read(input);
            out = Hex.encode(in);
            return SDCCodec.write(scope, out);
        } finally {
            SDCCodec.wipe(in, out);
        }
    }

    @Override
    public SensitiveDataContainer hexDecode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        byte[] in = null;
        byte[] out = null;
        try {
            in = SDCCodec.read(input);
            if (in.length % 2 != 0)
                throw new ELIBSecurityIllegalArgumentException("유효하지 않은 Hex 인코딩 데이터입니다 (홀수 길이)!");
            out = Hex.decode(in);
            return SDCCodec.write(scope, out);
        } catch (ELIBSecurityIllegalArgumentException | ELIBSecurityProcessException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new ELIBSecurityProcessException("유효하지 않은 Hex 입력입니다!", e);
        } finally {
            SDCCodec.wipe(in, out);
        }
    }

    @Override
    public @NotNull String backendName() {
        return "BouncyCastle FIPS 인코더";
    }
}
