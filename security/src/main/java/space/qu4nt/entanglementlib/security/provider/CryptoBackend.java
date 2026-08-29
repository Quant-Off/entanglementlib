package space.qu4nt.entanglementlib.security.provider;

/// FFI 경계를 통해 사용되는 보안 기능의 백엔드(backend) 선택지입니다.
///
/// # Note
/// [#ENTLIB_NATIVE]는 암호학적 검증이 충분히 이루어지지 않은 시험적(experimental) 백엔드입니다.
/// 프로덕션 환경에서는 [#JDK_VERIFIED], [#BOUNCY_CASTLE_FIPS], 또는 사용자가 직접 주입한 검증
/// 공급자를 사용하세요.
///
/// 서수(ordinal)는 하위 호환을 위해 뒤에만 추가합니다. 기존 값의 순서를 바꾸지 마세요.
public enum CryptoBackend {

    /// Rust `entlib-native` 레이어를 FFI로 호출하는 백엔드입니다. (미검증, 시험용)
    ENTLIB_NATIVE,

    /// JDK 표준 JCA(Java Cryptography Architecture) 공급자를 사용하는 검증된 백엔드입니다.
    JDK_VERIFIED,

    /// BouncyCastle FIPS(`bc-fips`) 경량 API를 직접 호출하는 검증된 백엔드입니다.
    ///
    /// JCA `Provider` 전역 등록([java.security.Security#addProvider])을 하지 않으므로 JVM 전역
    /// 상태를 오염시키지 않습니다. JDK 백엔드가 지원하지 않는 SHAKE(XOF) 가변 길이 출력과
    /// NIST SP 800-90A DRBG 기반 난수를 제공합니다.
    ///
    /// # Note
    /// `bc-fips`는 `compileOnly` 의존성이므로 이 백엔드를 선택하려면 사용자가 런타임 클래스패스에
    /// `bc-fips` 아티팩트를 직접 배포해야 합니다. 부재 시 공급자 설치 시점에 예외가 발생합니다.
    ///
    /// # Limitation
    /// `ChaCha20-Poly1305`는 FIPS 승인 알고리즘이 아니므로 `approved-only` 모드
    /// ([org.bouncycastle.crypto.CryptoServicesRegistrar#setApprovedOnlyMode])에서는 AEAD 연산이
    /// 거부됩니다. 다이제스트·난수는 `approved-only` 모드에서도 동작합니다.
    BOUNCY_CASTLE_FIPS,

//    BOUNCY_CASTLE
}
