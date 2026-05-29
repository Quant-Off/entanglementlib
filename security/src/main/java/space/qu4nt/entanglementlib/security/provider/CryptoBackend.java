package space.qu4nt.entanglementlib.security.provider;

/// FFI 경계를 통해 사용되는 보안 기능의 백엔드(backend) 선택지입니다.
///
/// # Note
/// [#ENTLIB_NATIVE]는 암호학적 검증이 충분히 이루어지지 않은 시험적(experimental) 백엔드입니다.
/// 프로덕션 환경에서는 [#JDK_VERIFIED] 또는 사용자가 직접 주입한 검증 공급자를 사용하세요.
public enum CryptoBackend {

    /// Rust `entlib-native` 레이어를 FFI로 호출하는 백엔드입니다. (미검증, 시험용)
    ENTLIB_NATIVE,

    /// JDK 표준 JCA(Java Cryptography Architecture) 공급자를 사용하는 검증된 백엔드입니다.
    JDK_VERIFIED
}
