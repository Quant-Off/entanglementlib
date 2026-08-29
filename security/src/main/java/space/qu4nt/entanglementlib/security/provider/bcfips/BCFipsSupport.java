package space.qu4nt.entanglementlib.security.provider.bcfips;

import org.jetbrains.annotations.ApiStatus;
import space.qu4nt.entanglementlib.core.exception.security.unchecked.ELIBSecurityIllegalArgumentException;

/// BouncyCastle FIPS(`bc-fips`) 모듈의 가용성과 자체 무결성 시험 상태를 검사하는 게이트입니다.
///
/// # Security Note
/// 이 클래스는 `org.bouncycastle` 타입을 시그니처나 본문에 직접 참조하지 않고 오직 리플렉션으로만
/// 접근합니다. `bc-fips`는 `compileOnly` 의존성이므로 런타임에 부재할 수 있으며, 부재 상태에서
/// 이 클래스를 적재해도 [NoClassDefFoundError]가 발생하지 않아야 하기 때문입니다. `BcFips*` 공급자
/// 구현체를 적재하기 전에 반드시 [#ensureAvailable]을 먼저 호출하세요. 검증기(verifier)가
/// 구현체 클래스 적재 시점에 BouncyCastle 타입을 미리 해석할 수 있습니다.
@ApiStatus.Internal
public final class BCFipsSupport {

    private static final String ARTIFACT = "org.bouncycastle:bc-fips";
    private static final String FIPS_STATUS_CLASS = "org.bouncycastle.crypto.fips.FipsStatus";

    private BCFipsSupport() {
        throw new AssertionError("cannot access");
    }

    /// `bc-fips` 모듈이 런타임 클래스패스에 존재하고 기동 자체 시험을 통과했는지 확인합니다.
    ///
    /// # Errors
    /// 모듈이 없거나 무결성·KAT 자체 시험에 실패해 준비 상태가 아니면
    /// [ELIBSecurityIllegalArgumentException]을 던집니다.
    public static void ensureAvailable() {
        final Class<?> fipsStatus;
        try {
            fipsStatus = Class.forName(FIPS_STATUS_CLASS, true, BCFipsSupport.class.getClassLoader());
        } catch (ClassNotFoundException | LinkageError e) {
            throw new ELIBSecurityIllegalArgumentException(
                    "BOUNCY_CASTLE_FIPS 백엔드를 선택했지만 런타임 클래스패스에서 '" + ARTIFACT + "' 모듈을 찾을 수 없습니다. "
                            + "이 의존성은 compileOnly이므로 배포물에 직접 포함해야 합니다.", e);
        }

        final boolean ready;
        try {
            ready = (boolean) fipsStatus.getMethod("isReady").invoke(null);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            throw new ELIBSecurityIllegalArgumentException(
                    "BouncyCastle FIPS 모듈의 자체 시험 상태를 확인하지 못했습니다!", e);
        }

        if (!ready)
            throw new ELIBSecurityIllegalArgumentException(
                    "BouncyCastle FIPS 모듈이 준비 상태가 아닙니다 -> " + statusMessage(fipsStatus));
    }

    private static String statusMessage(final Class<?> fipsStatus) {
        try {
            return String.valueOf(fipsStatus.getMethod("getStatusMessage").invoke(null));
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            return "(상태 메시지를 읽을 수 없음)";
        }
    }
}
