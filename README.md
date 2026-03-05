# EntanglementLib

[![Version](https://img.shields.io/badge/version-1.1.0%20Alpha-blue?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%20License%201.0.0-green?style=for-the-badge)](LICENSE)
[![Language](https://img.shields.io/badge/language-Java-orange?style=for-the-badge)](https://github.com/Quant-Off/entanglementlib)

![EntanglementLib](entanglementlib-logo.png)

얽힘 라이브러리(EntanglementLib)는 모든 보안 연산을 안전하며, 빠르게 처리하도록 설계된 군사급 보안 라이브러리입니다. 고전 및 양자-내성 암호화(Post-Quantum Cryptography, PQC) 기술을 제공하며, 이를 사용한 미래지향적 TLS 프로토콜을 제공합니다.

진화하는 디지털 위협 환경에 대응하여 최고 수준의 보안과 시스템 안정성을 제공하는 것을 목표로 합니다.

> [English README](README_EN.md)

## 핵심 철학

얽힘 라이브러리의 모든 설계는 '군사적 보안', '금융 및 대규모 엔터프라이즈 환경에서의 안전한 인프라 확립'을 위한 보안성(security)을 최우선 원칙으로 합니다. 얽힘 라이브러리는 잠재적 보안 취약점을 원천적으로 방지하고, 데이터 무결성을 보장하도록 구현되었습니다. 두 번째 핵심 가치는 안정성(stability) 으로, 예측 가능하고 일관된 성능을 보장하기 위해 Rust 네이티브 연산을 적용하여 매우 안전하게 메모리 효율성을 극대화하고, 체계적인 오류(또는 예외) 처리 메커니즘을 갖추었습니다.

## 기술

얽힘 라이브러리는 모든 보안 연산을 [Rust 기반 네이티브](https://github.com/Quant-Off/entlib-native)를 통해 수행합니다. 네이티브에선 `heap` 메모리 할당에 따른 가비지 컬렉터(Garbage Collection, GC)의 청소 메커니즘에서 발발될 수 있는 모든 보안 약점을 파훼합니다. Java 측의 민감 데이터를 `off-heap`으로 받아 작업을 수행하고, 호출자 또는 피호출자 패턴을 통해 해당 포인터의 데이터를 즉각적으로 안전하게 소거합니다.

Java 측에서 네이티브와 상호 작용할 때, 단순히 JNI(Java Native Interface) 기능이 사용되지 않습니다. 핵심적인 기술은 [JEP 389](https://openjdk.org/jeps/389), [JEP 454](https://openjdk.org/jeps/454) 개선안에 의거한 고급적 네이티브 호출 기능인 Linker, FFM API(Foreign Function & Memory API)이며, 네이티브 측에선 캡슐화된 로직을 통해 FFI(Foreign Function Interface)로 연동됩니다.

> [!TIP]
> 네이티브에 대한 배경 및 개요가 궁금하시다면 [이 곳](https://qu4nt.space/projects/entlib-native)을 참고하세요.
> 
> 또는 얽힘 라이브러리의 배경에 대해 궁금하시다면 [이 곳](https://qu4nt.space/projects/entanglementlib)을 참고하세요.

이 라이브러리 내에서 사용자의 데이터는 바이트 배열(`byte[]`)이나 문자 배열(`char[]`)로 관리되지 않습니다. 이러한 타입은 `heap` 메모리, 나아가 GC에게 주도권을 주는 셈입니다. 이러한 원시적 사용 대신 `SensitiveDataContainer` 객체를 사용할 수 있습니다. 이 객체는 민감 데이터의 소유권을 넘겨받고 네이티브에 안전히 넘겨 작업 처리를 안전하고 효율적으로 할 수 있도록 도와줍니다. 좀 더 구체적으로, 해당 객체는 [Rust의 RAII(Resource Acquisition Is Initialization) 패턴](https://doc.rust-lang.org/rust-by-example/scope/raii.html)과 유사하게 인스턴스화 시점에 자원을 획득하고 `close()` 호출 시점에 자원을 해제합니다. 이러한 개념은 Java에서 꽤 특이할 수도 있습니다.

## 멀티모듈

얽힘 라이브러리는 이제 멀티모듈 프로젝트입니다. 각 모듈의 역할은 작업 및 실용적 어노테이션, 보안 그리고 각종 편의성 도구를 포함한 유틸리티로 나눠집니다. 어노테이션 및 코어 모듈은 보안 모듈에서 핵심적으로 사용되지만, 보안 모듈은 다른 모듈에서 절대로 사용되지 않습니다.

| 모듈            | 기능                                                               |
|---------------|------------------------------------------------------------------|
| `security`    | 핵심 보안 모듈입니다. 네이티브와의 상호 작용을 위한 로직과, FFI를 통해 연동된 갖가지 보안 기능을 제공합니다. |
| `core`        | 예외, 국제화 및 비동기, 청크 작업, 문자열, 자료구조를 관리하는 유틸리티 기능을 제공합니다.            |
| `annotations` | 간편한 코드 설계 및 사용자의 코드 이해 복잡도를 개선하기 위한 어노테이션이 포함되어 있습니다.            |


## 기술 명세

얽힘 라이브러리에 대한 상세한 기술 명세를 작성 중에 있습니다.

## 벤치마킹 기록

얽힘 라이브러리에서 FFM API를 사용하여 Rust 네이티브 함수를 호출할 떄 발생하는 나노세컨드 지연 등 다양한 연산에 대한 브릿지 벤치마킹을 수행하고 있습니다. 이러한 작업은 성능 및 보안성에 직결되며, 최적의 코드를 창출하기 위해 중요한 역할을 합니다.

이 알파 버전에서 많은 벤치마킹 작업이 예정되어 있습니다. JMH(Java Microbenchmark Harness)를 통해 이 작업을 진행할 예정이며, 완료되는데로 새로운 문서에 정리하겠습니다.

## 기여

이 프로젝트는 현재 `Alpha` 버전이며, 아직 많이 부족합니다. 여러분의 피드백을 적극적으로 받을 준비가 이미 되어 있습니다. 얽힘 라이브러리는 단순히 PQC 알고리즘을 제공하는 것만이 아닌, 체계적으로 사용자 환경의 인프라 보안을 감시하고 사용자에게 해결책을 찾아주는 유능한 도구로써 사용되도록 개발됩니다. 최신 릴리즈부턴 이 신념에 강력한 초점을 맞출 것입니다.

## TODO

얽힘 라이브러리는 미래에 금융 및 보안 인프라 프로덕션에서 사용할 수 있도록 다음의 TODO를 명확히 하고자 합니다.

- [ ] 폐쇄망 환경 유용한 사용을 위한 Local Hosted 웹 개발
- [ ] TLS 통신 로직 추가
- [ ] 복합 검증 작업 준비 및 수행
- [ ] 커스텀 예외 최적화
- [ ] JPMS 적용 (멀티모듈 내에서도 패키지 모듈화)
  - 안전한 캡슐화와 일관된 호출(또는 사용) 패턴이 완성되면 JPMS를 통해 캡슐화된 패키지를 모듈로서 관리하려고 합니다.
- [ ] 외부 의존성 최소화
  - 이제 `1.1.0` 릴리즈부턴 `BouncyCastle` 의존성을 최소화하며, 끝내 제거하는 데 성공했습니다. 현재 코드 작성에 필요한 몇 가지 유용한 도구를 제공하는 의존성은 여전히 남아 있지만, 이들도 끝내 최소화될 예정입니다.
- [ ] `i18n` 업데이트
  - 최신 릴리즈 개발을 수행하며 다국어 지원을 많이 누락했습니다. 구성 설정에 따라 각 언어별로 로깅을 지원할 수 있도록 수정해야 합니다.

### 해결됨

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
- [X] 보안 기능에 대한 기술 명세 작성
    - **해결**: 얽힘 라이브러리의 중요한 보안 관련 기능을 [별도의 문서](TECHNICAL.md)에 작성했습니다.

## 라이선스

본 프로젝트는 `PolyForm Noncommercial License 1.0.0`을 따릅니다. 이 프로젝트 내에서 `entlib-native`를 동시 관리하는 탓에 라이선스가 가끔 `MIT`로 잘못 반영될 때가 있지만, 여전히 `PolyForm` 라이선스를 따른다는 것을 참고해주세요. 이 라이선스에 관해 자세한 내용은 [LICENSE](LICENSE) 파일을 참고하세요.

---

# 변경 사항

변경 사항은 [CHANGE.md](CHANGE.md) 문서에서 확인하실 수 있습니다. 이 문서는 `1.1.0` 릴리즈가 공개될 때 추가됩니다.