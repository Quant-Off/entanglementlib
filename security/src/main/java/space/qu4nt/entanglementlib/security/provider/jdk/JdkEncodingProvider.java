package space.qu4nt.entanglementlib.security.provider.jdk;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityProcessException;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;
import space.qu4nt.entanglementlib.security.data.SDCScopeContext;
import space.qu4nt.entanglementlib.security.data.SensitiveDataContainer;
import space.qu4nt.entanglementlib.security.provider.EncodingProvider;
import space.qu4nt.entanglementlib.security.provider.SDCCodec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

/// JDK 표준 라이브러리를 사용하는 검증된 [EncodingProvider] 구현입니다.
///
/// Base64는 [java.util.Base64], Hex는 [HexFormat](소문자)을 사용합니다.
@ApiStatus.Internal
public final class JdkEncodingProvider implements EncodingProvider {

    private static final HexFormat HEX = HexFormat.of();

    @Override
    public SensitiveDataContainer base64Encode(final @NotNull SDCScopeContext scope, final @NotNull SensitiveDataContainer input)
            throws ELIBSecurityProcessException {
        byte[] in = null;
        byte[] out = null;
        try {
            in = SDCCodec.read(input);
            out = Base64.getEncoder().encode(in);
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
            out = Base64.getDecoder().decode(in);
            return SDCCodec.write(scope, out);
        } catch (IllegalArgumentException e) {
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
            out = HEX.formatHex(in).getBytes(StandardCharsets.US_ASCII);
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
            out = HEX.parseHex(new String(in, StandardCharsets.US_ASCII));
            return SDCCodec.write(scope, out);
        } catch (IllegalArgumentException e) {
            // 홀수 길이 검증(ELIBSecurityIllegalArgumentException)은 별도 계층이므로 여기서 잡히지 않음
            throw new ELIBSecurityProcessException("유효하지 않은 Hex 입력입니다!", e);
        } finally {
            SDCCodec.wipe(in, out);
        }
    }

    @Override
    public @NotNull String backendName() {
        return "JDK 표준 (검증)";
    }
}
