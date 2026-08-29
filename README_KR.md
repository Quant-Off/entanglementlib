# EntanglementLib

[![Version](https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)
[![README-Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README.md)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%20License%201.0.0-green?style=for-the-badge)](LICENSE)
[![Language](https://img.shields.io/badge/language-Java-orange?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

![EntanglementLib](entanglementlib-logo.png)

얽힘 라이브러리(EntanglementLib)는 모든 보안 연산을 안전하며, 빠르게 처리하도록 설계된 라이브러리입니다. 연결된 [Rust 레이어(네이티브)](https://github.com/Quant-Off/entlib-native)를 통해 고전 및 양자-내성 암호화(Post-Quantum Cryptography, PQC) 기술을 제공하며, 이를 사용한 미래지향적 TLS 프로토콜을 제공합니다.

## 기술

얽힘 라이브러리는 모든 보안 연산을 **Rust 기반 네이티브**를 통해 수행합니다. 네이티브에선 `heap` 메모리 할당에 따른 가비지 컬렉터(Garbage Collection, GC)의 청소 메커니즘에서 발발될 수 있는 모든 보안 약점을 원천적으로 방지합니다. Java 측의 민감 데이터를 `off-heap`으로 받아 작업을 수행하고, 호출자 또는 피호출자 패턴을 통해 해당 포인터의 데이터를 즉각적으로 안전하게 소거합니다.

Java 측에서 네이티브와 상호 작용할 때 JNI(Java Native Interface) 기능을 사용하지 않습니다. 핵심 기술은 [JEP 389](https://openjdk.org/jeps/389), [JEP 454](https://openjdk.org/jeps/454) 개선안에 의거한 고급적 네이티브 호출 기능인 Linker, FFM API(Foreign Function & Memory API)이며, 네이티브 측에선 캡슐화된 로직을 통해 FFI(Foreign Function Interface)로 연동됩니다.

> [!TIP]
> 네이티브에 대한 배경 및 개요가 궁금하시다면 [이 곳](https://qu4nt.space/projects/entlib-native)을 참고하세요.
>
> 또는 얽힘 라이브러리의 배경에 대해 궁금하시다면 [이 곳](https://qu4nt.space/projects/entanglementlib)을 참고하세요.

이 라이브러리 내에서 사용자의 데이터는 바이트 배열(`byte[]`)이나 문자 배열(`char[]`)로 관리되지 않습니다. 이러한 타입은 `heap` 메모리에 쓰기(write)되어 GC에게 주도권을 줍니다. 이러한 원시적 사용 대신 `SensitiveDataContainer` 객체를 사용할 수 있습니다. 이 객체는 민감 데이터의 소유권을 넘겨받고 네이티브에 안전히 넘겨 작업 처리를 안전하고 효율적으로 할 수 있도록 도와줍니다. 좀 더 구체적으로, 해당 객체는 [Rust의 RAII(Resource Acquisition Is Initialization) 패턴](https://doc.rust-lang.org/rust-by-example/scope/raii.html)과 유사하게 인스턴스화 시점에 자원을 획득하고 `close()` 호출 시점에 자원을 해제합니다.

### 멀티모듈

얽힘 라이브러리는 멀티모듈 프로젝트입니다. 각 모듈의 역할은 작업 및 실용적 어노테이션과 각종 편의성 도구를 포함한 유틸리티로 나눠집니다. 어노테이션 및 코어 모듈은 보안 모듈에서 핵심적으로 사용되지만, 보안 모듈은 다른 모듈에서 절대로 사용되지 않습니다.

| 모듈                       | 기능                                                               |
|--------------------------|------------------------------------------------------------------|
| `security`               | 핵심 보안 모듈입니다. 네이티브와의 상호 작용을 위한 로직과, FFI를 통해 연동된 갖가지 보안 기능을 제공합니다. |
| `core`                   | 예외, 국제화 및 비동기, 청크 작업, 문자열, 자료구조를 관리하는 유틸리티 기능을 제공합니다.            |
| `annotations`            | 간편한 코드 설계 및 사용자의 코드 이해 복잡도를 개선하기 위한 어노테이션이 포함되어 있습니다.            |
| `internal-shared-server` | 폐쇄 환경의 인프라를 형성 및 관리할 수 있는 기능이 포함되어 있습니다.                         |

## 주의 및 보안 공급자 설정

**얽힘 라이브러리(Java)에서 네이티브로 호출되는 보안 기능인 `entlib-native`는 암호학적 검증이 이루어지지 않았습니다.**

> [!IMPORTANT]
> 암호 모듈을 검증받는 데에는 많은 시간이 필요합니다. 따라서 `entlib-native` 공급자는 **"반드시 실험(연구)적 용도로만"** 사용해야 합니다.

사용자는 Rust 레이어에 구현된 '보안 기능 공급자'를 `entlib-native`가 아닌 '이미 검증된 안전한 공급자'로 변경하실 수 있습니다.

### 공급자 설정

FFI 경계를 통해 사용되는 모든 보안 기능(다이제스트, 인코딩, AEAD, 난수)은 `CryptoProviderConfig`로 백엔드를 선택할 수 있습니다. 선택지는 다음과 같습니다.

- `CryptoBackend#JDK_VERIFIED` - JDK 표준 JCA(`MessageDigest`, `Cipher`, `SecureRandom`, `java.util.Base64`, `HexFormat`)를 사용하는 검증된 백엔드 (**기본값**)
- `CryptoBackend#BOUNCY_CASTLE_FIPS` - BouncyCastle FIPS(`bc-fips`) 경량 API를 직접 호출하는 검증된 백엔드
- `CryptoBackend#ENTLIB_NATIVE` - `entlib-native` FFI 백엔드 (미검증, 실험용)
- 사용자가 직접 구현한 검증 공급자 인스턴스 주입 (예: HSM, PKCS#11, 사내 검증 라이브러리)

기본값은 **검증된 JDK 백엔드**입니다. 따라서 별도 설정 없이 초기화하면 미검증 네이티브 대신 검증된 공급자가 사용됩니다.

```java
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityFacade;
import space.qu4nt.entanglementlib.security.data.HeuristicArenaFactory;
import space.qu4nt.entanglementlib.security.provider.CryptoBackend;
import space.qu4nt.entanglementlib.security.provider.CryptoProviderConfig;

class Main {
    static void main() {
        // 1) 기본값 (전체 검증된 JDK 백엔드)
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(null, HeuristicArenaFactory.ArenaMode.AUTO));
        
        // 2) 전체 BouncyCastle FIPS (SHAKE 및 SP 800-90A DRBG 지원)
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        null, HeuristicArenaFactory.ArenaMode.AUTO,
                        CryptoProviderConfig.bouncyCastleFipsDefaults()));
        
        // 3) 전역 + 기능별 혼합 + 외부 JCA 공급자 + 커스텀 공급자 주입
        CryptoProviderConfig providers = CryptoProviderConfig.builder()
                .useVerifiedProviders()                   // 전역 기본을 검증된 JDK로
                .digest(CryptoBackend.BOUNCY_CASTLE_FIPS) // 다이제스트만 BC FIPS로 (SHAKE 필요)
                .aead(CryptoBackend.ENTLIB_NATIVE)        // AEAD만 네이티브로 (실험)
                .jcaProviderName("BC")                    // JDK 백엔드가 사용할 JCA 공급자명
                .random(myVerifiedRandomProvider)         // 난수는 사용자 정의 검증 공급자
                .build();
        
        EntanglementLibSecurityFacade.initialize(
                EntanglementLibSecurityConfig.create(
                        nativeSpecContext, HeuristicArenaFactory.ArenaMode.AUTO, providers));
        
        // 4) 전체 entlib-native (실험용)
        EntanglementLibSecurityConfig.create(nativeSpecContext, null, CryptoProviderConfig.nativeDefaults());
    }
}
```

> [!TIP]
> 모든 기능이 검증된(또는 커스텀) 공급자로 해석되면(`requiresNative() == false`) 얽힘 라이브러리는 미검증 네이티브 바이너리를 **로드하지 않습니다.** 폐쇄 환경에서 네이티브 바이너리를 배포하지 않고도 검증된 보안 연산만 사용할 수 있습니다.

> [!NOTE]
> **검증된 JDK 백엔드와 BouncyCastle FIPS 백엔드는 연산 시간 동안 민감 데이터가 JVM `heap`에 잠시 노출**됩니다. 두 백엔드 모두 `byte[]`로만 동작하기 때문입니다. 라이브러리는 사용한 임시 `byte[]`를 즉시 0으로 소거하지만, 이는 검증된 정확성을 위한 의도된 절충입니다. 또한 **양자 네트워크 난수는 두 백엔드 모두 대응 소스가 없어 지원하지 않습니다.** **SHAKE(XOF) 가변 길이 출력은 JDK 표준에 대응이 없어 JDK 백엔드가 지원하지 않으며**, BouncyCastle FIPS 백엔드 또는 XOF 지원 사용자 정의 공급자가 필요합니다.

### BouncyCastle FIPS 백엔드

`CryptoBackend#BOUNCY_CASTLE_FIPS`는 JCA `Provider` 전역 등록(`Security.addProvider`)을 하지 않고 `bc-fips` 경량 API를 직접 호출합니다. JVM 전역 상태를 오염시키지 않으므로 격리 원칙에 부합하며, JDK 백엔드가 지원하지 않는 다음 기능을 제공합니다.

| 기능      | 구현                                                    |
|---------|-------------------------------------------------------|
| 다이제스트   | `FipsSHS` SHA-2 · SHA-3 (FIPS 승인)                     |
| SHAKE   | `FipsSHS` SHAKE128 · SHAKE256 XOF (FIPS 승인)           |
| AEAD    | `ChaCha20-Poly1305` (RFC 8439, **FIPS 미승인**)          |
| 난수      | `FipsDRBG` HMAC-DRBG-SHA512 (NIST SP 800-90A, 예측 저항성) |
| 인코딩     | `Base64` · `Hex`                                      |

> [!IMPORTANT]
> `bc-fips`는 `compileOnly` 의존성입니다. 에어갭 배포에서 BouncyCastle을 포함하지 않을 선택지를 남기기 위한 결정이며, 이 백엔드를 사용하려면 **런타임 클래스패스에 `org.bouncycastle:bc-fips`를 직접 포함**해야 합니다. 모듈이 없거나 기동 자체 시험에 실패하면 공급자 설치 시점에 명확한 예외가 발생하고 기존 구성이 그대로 유지됩니다.

> [!WARNING]
> `ChaCha20-Poly1305`는 FIPS 승인 알고리즘이 아니라 `bc-fips`의 `general` 계열에 속합니다. 따라서 `CryptoServicesRegistrar.setApprovedOnlyMode(true)`로 approved-only 모드를 켠 스레드에서는 **AEAD 연산이 거부**됩니다. 다이제스트 · SHAKE · 난수는 approved-only 모드에서도 동작합니다. approved-only 모드에서 AEAD가 필요하면 AES-GCM 기반 사용자 정의 공급자를 주입하세요.

## 폐쇄망 공유 서버

`internal-shared-server`(ISS) 모듈은 폐쇄망에서 여러 내부 노드가 접속하는 보안 공유 서버입니다. 공개 인터넷 CA 신뢰 체인을 배제하고 사전 공유 키(PSK)로 양측을 상호 인증하며, 모든 레코드는 `ChaCha20-Poly1305`로 보호됩니다. 검증된 JDK 공급자만으로 동작하므로 네이티브 바이너리 배포 없이 사용할 수 있습니다. 코드레벨 임베드 API(`ISSServer`·`ISSClient`)와 CLI 두 경로로 제어합니다.

> [!NOTE]
> 키 확립에 DH/KEM을 사용하지 않으므로 순방향 비밀성(PFS)은 제공하지 않습니다. PSK가 노출되면 과거·미래 트래픽이 위험하므로 강한 PSK와 주기적 교체로 운용하세요. 서버는 기본적으로 루프백(127.0.0.1)에만 바인드하며, LAN 노출은 명시적 옵트인(opt-in)이 필요합니다.

### 실행 파일 준비

애플리케이션 배포본을 생성하면 실행 스크립트가 만들어집니다.

```bash
./gradlew :internal-shared-server:installDist
# 생성 위치
# internal-shared-server/build/install/internal-shared-server/bin/internal-shared-server

# 편의상 alias 등록 (선택)
alias iss="$(pwd)/internal-shared-server/build/install/internal-shared-server/bin/internal-shared-server"
```

또는 Gradle로 바로 실행할 수 있습니다.

```bash
./gradlew :internal-shared-server:run --args="--help"
```

### CLI 사용법

```text
iss serve   --port N [--bind 127.0.0.1] (--psk-file F | --psk-env VAR)
            [--max-conn 64] [--allow-nonloopback] [--allow-peer IP]...
iss ping    --port N [--host 127.0.0.1] (--psk-file F | --psk-env VAR)
iss put     --port N [--host H] (--psk-file F | --psk-env VAR)
            --key K (--value V | --value-file F | --stdin)
iss get     --port N [--host H] (--psk-file F | --psk-env VAR) --key K [--out FILE]
iss del     --port N [--host H] (--psk-file F | --psk-env VAR) --key K
iss list    --port N [--host H] (--psk-file F | --psk-env VAR)
iss status  --port N [--host H] (--psk-file F | --psk-env VAR)
iss gen-psk [--bytes 32] [--out FILE]
iss --help | --version
```

| 명령        | 설명                                               |
|-----------|--------------------------------------------------|
| `serve`   | 서버를 바인드하고 연결 수용 시작 (Ctrl-C 로 종료)                 |
| `ping`    | 핸드셰이크 후 서버 응답 확인                                 |
| `put`     | 키에 값을 저장 (값은 인자·파일·표준입력 중 하나)                    |
| `get`     | 키의 값을 조회 (`--out` 지정 시 파일 저장, 없으면 표준출력, 미존재 시 1) |
| `del`     | 키를 삭제                                            |
| `list`    | 저장된 키 목록 출력                                      |
| `status`  | 서버 상태 조회                                         |
| `gen-psk` | 보안 난수로 PSK 생성 (`--out` 없으면 hex 를 표준출력)           |

> [!IMPORTANT]
> PSK는 평문 명령행 인자로 받지 않습니다(프로세스 목록 노출 방지). raw 바이트 키 파일(`--psk-file`) 또는 hex 환경변수(`--psk-env`)로만 입력하며, 최소 32바이트를 요구합니다. 로그는 표준오류로, 명령 결과 데이터는 표준출력으로 분리됩니다.

### 빠른 시작

```bash
# 1) PSK 생성 (raw 32바이트 키 파일, 소유자 전용 권한으로 저장)
iss gen-psk --out infra.psk

# 2) 서버 기동 (루프백 기본)
iss serve --port 8443 --psk-file infra.psk

# 3) 다른 터미널에서 클라이언트 명령
iss ping   --port 8443 --psk-file infra.psk
iss put    --port 8443 --psk-file infra.psk --key greeting --value "Hello"
iss get    --port 8443 --psk-file infra.psk --key greeting
iss list   --port 8443 --psk-file infra.psk
iss status --port 8443 --psk-file infra.psk
iss del    --port 8443 --psk-file infra.psk --key greeting

# 환경변수(hex)로 PSK 전달
export ISS_PSK=$(iss gen-psk)
iss ping --port 8443 --psk-env ISS_PSK
```

## 기여

여러분의 피드백을 적극적으로 받을 준비가 되어 있습니다. 얽힘 라이브러리는 단순히 PQC 알고리즘을 제공하는 것만이 아닌, 체계적으로 사용자 환경의 인프라 보안을 감시하고 사용자에게 해결책을 찾아주는 유능한 도구로써 사용되도록 개발됩니다. 최신 릴리즈부턴 이 신념에 강력한 초점을 맞출 것입니다.

## TODO

얽힘 라이브러리는 미래에 금융 및 보안 인프라 프로덕션에서 사용할 수 있도록 다음의 TODO를 명확히 하고자 합니다.

- [ ] 폐쇄망 환경 유용한 사용을 위한 Local Hosted 웹 개발
  - 현재 ISS는 CLI와 임베드 API(`ISSServer`·`ISSClient`)로만 제어합니다. 웹 기반 관리 콘솔은 아직 없습니다.
- [ ] TLS 통신 로직 추가
  - ISS의 PSK 상호 인증 + ChaCha20-Poly1305 보안 채널은 구현을 완료했습니다.
  - `security` 모듈에 `ExternalTLS` 파사드 골격을 추가했으나, ML-KEM 키 확립과 ChaCha20-Poly1305 레코드 AEAD, RNG nonce 생성이 네이티브 FFI에 노출되기 전까지 핸드셰이크는 비활성(스텁) 상태입니다.
- [ ] 복합 검증 작업 준비 및 수행
  - 보안 공급자 SPI(`CryptoProviderConfig`)를 추가해 미검증 네이티브 대신 검증된 JDK 공급자(또는 커스텀 공급자)를 선택할 수 있습니다. `entlib-native` 자체의 암호학적 검증은 계속 진행 중입니다.
- [x] 커스텀 예외 최적화
  - checked/unchecked 및 core/security 계층으로 분리한 예외 체계와 i18n 연동 `ExceptionLogger`를 구성했습니다.
- [ ] JPMS 적용 (멀티모듈 내에서도 패키지 모듈화)
  - 안전한 캡슐화와 일관된 호출(또는 사용) 패턴이 완성되면 JPMS를 통해 캡슐화된 패키지를 모듈로서 관리하려고 합니다.
- [ ] `i18n` 업데이트
  - `core`의 `EntanglementLibCoreI18n`과 `en_US`·`ko_KR` 메시지 번들을 갖췄습니다. 다만 구성 설정에 따라 각 언어별 로깅을 자동 적용하는 연동은 아직 더 다듬어야 합니다.

## 라이선스

본 프로젝트는 `PolyForm Noncommercial License 1.0.0`을 따릅니다. 이 프로젝트 내에서 `entlib-native`를 동시 관리하는 탓에 라이선스가 가끔 `MIT`로 잘못 반영될 때가 있지만, 여전히 `PolyForm` 라이선스를 따른다는 것을 참고해주세요. 이 라이선스에 관해 자세한 내용은 [LICENSE](LICENSE) 파일을 참고하세요.
