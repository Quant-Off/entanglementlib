package space.qu4nt.entanglementlib.security.provider.bcfips;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.provider.AeadProvider;
import space.qu4nt.entanglementlib.security.provider.DigestProvider;
import space.qu4nt.entanglementlib.security.provider.EncodingProvider;
import space.qu4nt.entanglementlib.security.provider.RandomProvider;

/// BouncyCastle FIPS 공급자 구현체를 생성하는 유일한 진입점입니다.
///
/// # Security Note
/// 모든 팩토리 메소드가 라이브러리 공통 인터페이스 타입만 반환하므로, 호출자 클래스를 검증(verify)할
/// 때 JVM이 `org.bouncycastle` 타입을 해석할 필요가 없습니다. 덕분에 `bc-fips`가 런타임에 없어도
/// 호출자 클래스는 정상 적재되며, 이 클래스를 처음 참조하는 시점에야 BouncyCastle 타입이 적재됩니다.
/// 따라서 호출자는 이 클래스의 메소드를 호출하기 직전에 반드시 [BCFipsSupport#ensureAvailable]로
/// 모듈 가용성을 먼저 확인해야 합니다.
@ApiStatus.Internal
public final class BCFipsProviderFactory {

    private BCFipsProviderFactory() {
        throw new AssertionError("cannot access");
    }

    public static @NotNull DigestProvider digest() {
        return new BCFipsDigestProvider();
    }

    public static @NotNull EncodingProvider encoding() {
        return new BCFipsEncodingProvider();
    }

    public static @NotNull AeadProvider aead() {
        return new BCFipsAeadProvider();
    }

    public static @NotNull RandomProvider random() {
        return new BCFipsRandomProvider();
    }
}
