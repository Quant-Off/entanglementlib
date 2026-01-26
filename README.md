# EntanglementLib

[![Version](https://img.shields.io/badge/version-1.1.0_Alpha-blue.svg)](https://github.com/Quant-Off/entanglementlib)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%20License%201.0.0-green.svg)](LICENSE)
![Language](https://img.shields.io/badge/language-Java-orange.svg)

![EntanglementLib](entanglementlib-logo.png)

얽힘 라이브러리(EntanglementLib)는 양자 내성 암호(Post-Quantum Cryptography, PQC) 기술을 기반으로 설계된 고성능 보안 및 유틸리티 라이브러리입니다. 본 라이브러리는 진화하는 디지털 위협 환경에 대응하여 최고 수준의 보안과 시스템 안정성을 제공하는 것을 목표로 합니다.

## 핵심 철학

얽힘 라이브러리의 모든 설계는 보안성(security) 을 최우선 원칙으로 합니다. 라이브러리는 잠재적 보안 취약점을 원천적으로 방지하고, 데이터 무결성을 보장하도록 구현되었습니다. 두 번째 핵심 가치는 안정성(stability) 으로, 예측 가능하고 일관된 성능을 보장하기 위해 메모리 효율성을 극대화하고 체계적인 오류 처리 메커니즘을 갖추었습니다.

## 강점

얽힘 라이브러리는 다음의 강점을 보유하고 있습니다.

1. 잔류 데이터 방지 (Anti-Data Remanence) 및 메모리 소거
   - 자바의 메모리 관리 모델인 가비지 컬렉터(Garbage Collection, GC)가 보안에 취약할 수 있다는 점을 정확히 파악하고 이를 기술적으로 극복하기 위한 기술이 탑재되었습니다.
   - 이 기술을 위해 `entlib-native` 네이티브 라이브러리를 사용하여 안전하게 소거하도록 설계했습니다.
   - 모든 민감 정보를 안전하게 관리하기 위해 [데이터 컨테이너 기능](https://github.com/Quant-Off/entanglementlib/blob/master/src/main/java/space/qu4nt/entanglementlib/entlibnative/SensitiveDataContainer.java)을 제공합니다.
2. 최신 PQC 표준 준수
   - FIPS 203, 204, 205에 따른 ML-KEM, ML-DSA, SLH-DSA 등의 NIST 표준화가 완료된 최신 알고리즘을 네이티브에서 처리하도록 하여 안전한 연산이 가능합니다.
   - `BouncyCastle Lightweight API`를 사용하여 고전 알고리즘을 사용하고, 내부적인 데이터 잔류 현상을 제거했습니다.
3. 아키텍처 및 디자인 패턴
   - 팩토리 패턴 및 인터페이스를 명확히 분리했습니다. [암호화 알고리즘은 전략적](https://github.com/Quant-Off/entanglementlib/tree/master/src/main/java/space/qu4nt/entanglementlib/security/crypto)으로 호출하여 사용할 수 있습니다.
4. 예외 처리
   - 표준 예외를 그대로 던지지 않도록 했습니다. 얽힘 라이브러리만의 커스텀 예외 클래스로 래핑하여 명확한 문맥(context)을 제공했습니다.
   - 보안 측면에서 문제를 발견한 경우, 시스템이 해결 방법을 제시하고, 우려되는 공격(해킹)을 방어하도록 설계했습니다.

## 주요 기능

얽힘 라이브러리는 강력한 암호화 기능과 개발 생산성 향상을 위한 유틸리티를 포함합니다.

| 모듈                       | 기술 명세                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `security.crypto`        | 양자 내성 암호(PQC) 및 현대 암호화 알고리즘을 제공합니다.<br/>- **PQC (NIST 표준)**: `ML-DSA` (Digital Signature Algorithm), `ML-KEM` (Key Encapsulation Mechanism), `SLH-DSA`를 지원하여 양자 컴퓨팅 시대에 대응하는 보안 체계를 구축합니다.<br/>- **대칭키 암호**: `ChaCha20-Poly1305` AEAD(Authenticated Encryption with Associated Data)를 지원하여 높은 수준의 기밀성과 무결성을 동시에 제공합니다.<br/>- **고성능 연산**: 주요 알고리즘은 SIMD(Single Instruction, Multiple Data) 명령어 셋을 활용하여 병렬 처리를 극대화하고 연산 속도를 최적화합니다.<br/>- **전략 패턴**: `RegistrableStrategy` 및 `EntLibCryptoRegistry`를 통해 알고리즘을 유연하게 등록하고 사용할 수 있습니다. |
| `security.communication` | 안전한 통신을 위한 세션 및 TLS 관련 기능을 제공합니다.<br/>- **세션 관리**: `Session`, `Participant`, `SessionConfig` 등을 통해 안전한 세션을 생성하고 관리합니다.<br/>- **TLS 지원**: `Server`, `ServerConfig` 등을 통해 TLS 기반의 보안 통신 채널을 구축할 수 있습니다.                                                                                                                                                                                                                                                                                                                             |
| `entlibnative`           | 네이티브 라이브러리와의 연동을 담당합니다.<br/>- **데이터 보호**: `SensitiveDataContainer`를 통해 민감한 데이터를 안전하게 관리하고 소거합니다.<br/>- **네이티브 연동**: `NativeLinkerManager`를 통해 Rust 등으로 작성된 고성능 네이티브 라이브러리를 로드하고 사용합니다.                                                                                                                                                                                                                                                                                                                                            |
| `util`                   | 보안 및 개발 편의성을 고려한 고성능 유틸리티를 제공합니다.<br/>- **입출력 및 청크 처리**: `EntFile`, `ChunkProcessor` 등을 통해 대용량 파일 및 데이터를 효율적으로 처리합니다.<br/>- **보안 유틸리티**: `Password`, `SecureCharBuffer` 등을 통해 비밀번호 및 민감한 문자열을 안전하게 다룹니다.<br/>- **기타**: `Hex`, `Hash`, `Async` 등 다양한 유틸리티 클래스를 제공합니다.                                                                                                                                                                                                                                                              |
| `exception`              | 안정적인 오류 처리를 위한 체계적인 예외 계층 구조를 제공합니다.<br/>- **보안 예외**: `EntLibSecureException` 및 하위 클래스들을 통해 보안 관련 오류를 명확하게 처리합니다.<br/>- **암호화 예외**: `EntLibCryptoException` 등을 통해 암호화 과정에서 발생하는 오류를 세분화하여 관리합니다.<br/>- **치명적 오류**: `EntLibError` 및 하위 클래스들을 통해 시스템의 치명적인 오류를 정의합니다.                                                                                                                                                                                                                                                               |

## 시작하기

### 1. 요구 사항

얽힘 라이브러리는 다음의 환경에서 개발되었습니다. 다른 버전에 대한 세부적인 테스트는 진행되지 않은 상태입니다.

- Java 25
- Gradle 9.2.0

얽힘 라이브러리는 NIST FIPS 203, 204, 205 표준화에 포함된 알고리즘을 안정적으로 사용하기 위해 Java 25 이상의 버전을 사용합니다.

### 2. 환경 변수 설정

`EntanglementLib`의 정상적인 동작을 위해 다음 환경 변수 설정이 필요합니다.

| 변수명                     | 설명                                             | 기본값 | 필수 여부 |
|-------------------------|------------------------------------------------|-----|-------|
| `ENTLIB_NATIVE_BIN`     | 네이티브 라이브러리의 바이너리가 포함된 디렉터리 경로를 지정합니다.          | -   | 필수    |
| `ENTANGLEMENT_HOME_DIR` | 얽힘 라이브러리 내부에서 사용되는 리소스가 저장될 디렉터리 경로를 지정합니다.    | -   | 필수    |

```bash
# 예시: Linux/macOS
export ENTLIB_NATIVE_BIN="/path/to/entlib-native/release"
export ENTANGLEMENT_HOME_DIR="/path/to/entanglementlib/"

# 예시: Windows
setx ENTLIB_NATIVE_BIN "C:\path\to\entlib-native\release"
setx ENTANGLEMENT_HOME_DIR "C:\path\to\entanglementlib\"
```

## TODO

이 프로젝트는 아직 많이 부족합니다. 얽힘 라이브러리는 미래에 금융 및 보안 인프라 프로덕션에서 사용할 수 있도록 다음의 TODO를 명확히 하고자 합니다.

- [X] Java 모듈 시스템(JPMS)과 리플렉션의 충돌 문제
  - `KeyDestroyHelper`에서 `Field.setAccessible(true)`를 사용하여 `BouncyCastle` 내부나 자바 표준 라이브러리의 `private` 필드를 수정하고 있습니다. Java 17 이후 강력한 캡슐화(strong encapsulation) 정책으로 인해, 실행 시 `--add-opens` JVM 옵션 없이는 `InaccessibleObjectException`이 발생할 확률이 매우 높습니다.
  - JVM 옵션 `--add-opens java.base/java.security=ALL-UNNAMED`를 추가하여 JPMS 보안 경고를 우회할 수 있습니다.
    - **해결**: 이 문제를 해결하기 위해 큰 고민을 하지 않았습니다. 왜냐하면 `1.1.0` 릴리즈부턴 `BC Lightweight API`를 사용하기로 결정했기 때문입니다. 저수준 접근으로 기존 JCA/JCE의 몇 가지 제약을 회피하는 것이 첫 번째 목표였습니다. 즉, 아직 여전히 리플렉션을 통한 접근이 필요불가결 합니다. 키를 생성한다던가, 내부 암호화 엔진을 호출해야 하는 때에는 유연하게 대응하지 못 할 수 있다는 말이죠. 이러한 복합적인 문제를 해결하기 위해 `entlib-native` 네이티브 라이브러리를 도입했고,얽힘 라이브러리의 `BC` 의존성을 최소화하는 데 초점을 맞추려고 합니다.
- [X] 성능 대 보안 트레이드오프
  - 모든 입출력에 대해 방어적 복사(deep copy)를 수행하고 있습니다. 수 기가바이트 단위의 대용량 데이터를 처리하거나 높은 처리량(Tick Per Second, TPS)이 필요한 서버 환경에서는 잦은 메모리 할당과 가비지 컬렉터 부하로 성능 저하가 발생할 수 있습니다. 기존 알고리즘 클래스만 봐도 인스턴스에 데이터를 바인딩하는 모습이 보입니다.
    - **해결**: `entlib-native` 네이티브 라이브러리를 추가하여 메모리 관련 연산은 전부 `Rust` 측에서 처리하게끔 설계했습니다. 이렇게 되면 이제 `Java` 측에선 단순히 순수 전달받는 바이트 배열같은 민감 데이터만을 소거하면 됩니다. `Rust`가 뒤에서 든든하게 메모리 연산을 취해 줄 겁니다.
- [X] 난수 및 Nonce 관리
  - `ChaCha20Poly1305`에서 `InternalFactory.getSafeRandom()`을 사용해 논스값 `Nonce`를 생성합니다. 같은 키로 `Nonce`가 재사용되면 `ChaCha20Poly1305`의 보안성은 완전히 무너집니다.
    - **해결**: 이 문제도 `entlib-native` 네이티브 라이브러리로 해결됐습니다. 이제 `Rust` 측에서 `ChaCha20` 기반의 `CSPRNG`를 만들고, `Rust` 측에서만 사용됩니다. 말인 즉슨, 모든 암호학적 연산은 이제 `Rust`만이 수행한다는 것입니다!
- [ ] 공급자 유동화 및 팩토리 최적화
  - 사용자의 선택에 따라 Java의 기본 공급자를 사용할 수 있도록 수정해야 합니다. 그리고 `InternalFactory` 클래스를 포함한 대부분의 클래스에서 제공되는 팩토리를 최적화해야 합니다.
- [ ] 전체 디자인 패턴 최적화
  - 현재 코드는 스파게티라고 해도 과언이 아닐 만큼 더러운 부분이 많이 보입니다. 제 방처럼 쾌적한 코드를 작성할 수 있도록 수정해야 합니다.
- [ ] `BouncyCastle` 의존성 최소화
  - 'Java 모듈 시스템(JPMS)과 리플렉션의 충돌 문제 해결'에서 언급했다시피, 이제 `1.1.0` 릴리즈부턴 `BC` 의존성을 최소화할겁니다. AES, ARIA, ChaCha20 같은 고전 알고리즘은 여전히 `BC` 의존성이 필요하기 때문에 의존성을 완전히 없애자는 말은 아니예요!
- [ ] `i18n` 업데이트
  - 최신 릴리즈 개발을 수행하며 다국어 지원을 많이 누락했습니다. 구성 설정에 따라 각 언어별로 로깅을 지원할 수 있도록 수정해야 합니다.

## 기여

초기 버전에서 얽힘 라이브러리는 'BouncyCastle 래퍼', '어중간한 데이터 소거', ... 와 같이 정말 애매모호한 목표를 가지고 있었습니다. 이 부분에 대해 꽤 많은 시간을 투자해 곰곰히 생각했으며, 얽힘 라이브러리만의 고유한 목표를 다시금 정립했습니다.

이제 얽힘 라이브러리는 단순히 PQC 알고리즘을 제공하는 것만이 아닌, 체계적으로 사용자 환경의 인프라 보안을 감시하고 사용자에게 해결책을 찾아주는 유능한 도구로써 사용되도록 개발됩니다. 최신 릴리즈부턴 이 신념에 강력한 초점을 맞출 것입니다.

그렇기 때문에... 얽힘 라이브러리의 궁극적 목표를 완성시키기 위해 여러 개발자분들의 힘이 필요합니다. 언제든 코드에 대한 피드백을 남겨주세요. 퀀트 팀에게 아주아주 큰 힘이 됩니다!

## Alpha

현재 얽힘 라이브러리는 뭉친 업데이트 내용을 재빨리 반영하기 위해 꽤 성급하게 `1.1.0-Alpha`를 공개한 상태입니다. 이 버전의 안정화 버전은 `1.1.0` 정식 릴리즈로 수정되서 반영될 예정입니다. 아무래도 1인 개발이다 보니 속도가 더뎌지는 문제가 있으나, 모든 수정까지 얼마 남지 않았습니다.

## 라이선스

본 프로젝트는 `PolyForm Noncommercial License 1.0.0`을 따릅니다. 이 프로젝트 내에서 `entlib-native`를 동시 관리하는 탓에 라이선스가 가끔 `MIT`로 잘못 반영될 때가 있지만, 여전히 `PolyForm` 라이선스를 따른다는 것을 참고해주세요. 이 라이선스에 관해 자세한 내용은 [LICENSE](LICENSE) 파일을 참고하세요.

---

# 변경 사항

변경 사항은 [CHANGE.md](CHANGE) 문서에서 확인하실 수 있습니다. 이 문서는 `1.1.0` 릴리즈가 공개될 때 추가됩니다.