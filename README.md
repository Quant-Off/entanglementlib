# EntanglementLib

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Quant-Off/entanglementlib)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%20License%201.0.0-green.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-Java-orange.svg)](#)

얽힘 라이브러리(EntanglementLib)는 양자 내성 암호(Post-Quantum Cryptography, PQC) 기술을 기반으로 설계된 고성능 보안 및 유틸리티 라이브러리입니다. 본 라이브러리는 진화하는 디지털 위협 환경에 대응하여 최고 수준의 보안과 시스템 안정성을 제공하는 것을 목표로 합니다.

## 핵심 철학

얽힘 라이브러리의 모든 설계는 보안성(security) 을 최우선 원칙으로 합니다. 라이브러리는 잠재적 보안 취약점을 원천적으로 방지하고, 데이터 무결성을 보장하도록 구현되었습니다. 두 번째 핵심 가치는 안정성(stability) 으로, 예측 가능하고 일관된 성능을 보장하기 위해 메모리 효율성을 극대화하고 체계적인 오류 처리 메커니즘을 갖추었습니다.

## 강점

얽힘 라이브러리는 다음의 강점을 보유하고 있습니다.

1. 잔류 데이터 방지 (Anti-Data Remanence) 및 메모리 소거
   - 자바의 메모리 관리 모델인 가비지 컬렉터(Garbage Collection, GC)가 보안에 취약할 수 있다는 점을 정확히 파악하고 이를 기술적으로 극복하기 위한 기술이 탑재되었습니다.
   - 모든 민감 정보 생성 로직엔 사용 후 즉시 메모리를 덮어쓰는 Wiping 패턴 또는 리플렉션을 통한 영소거(zeroing) 기능이 탑재되어 있습니다.
   - 알고리즘을 제공하는 클래스는 `AutoCloseable`을 구현하여 `try-with-resources` 블록을 강제하고, 스코프를 벗어나는 즉시 키와 평문을 파기하도록 설계되었습니다.
2. 방어적 복사 (Defensive Copying)
   - 생성자와 Getter 메소드에서 배열을 단순히 참조 할당하지 않고 `clone()` 또는 `Arrays.copyOf()`를 수행하여 외부에서의 악의적인 변경이나 실수로 인한 데이터 오염을 방지합니다.
3. 최신 PQC 표준 준수
   - FIPS 203, 204, 205에 따른 ML-KEM, ML-DSA, SLH-DSA(Sphincs+) 등의 NIST 표준화가 완료된 최신 알고리즘을 `BouncyCastle 1.83`을 통해 빠르게 적용했습니다.
4. 아키텍처 및 디자인 패턴
   - 팩토리 패턴 및 인터페이스를 분리했습니다. `InternalFactory`클래스를 통해 구현체를 숨기고, `EntLibCryptoService`, `KeyEncapsulateService` 등의 인터페이스로 기능을 노출하여 얽힘 라이브러리의 확장성과 유지보수성을 높였습니다.
5. 예외 처리
   - 표준 예외를 그대로 던지지 않고 `EntLibSecureIllegalStateException`, `EntLibAlgorithmSettingException` 등의 커스텀 예외 클래스로 래핑하여 명확한 문맥(context)을 제공했습니다.

## 주요 기능

얽힘 라이브러리는 강력한 암호화 기능과 개발 생산성 향상을 위한 유틸리티를 포함합니다.

| 모듈            | 기술 명세                                                                                                                                                                                                                                                                                                                                                                                                                 |
|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `algorithm`   | 양자 내성 암호(PQC) 및 현대 암호화 알고리즘을 제공합니다.<br/>- PQC (NIST 표준): `ML-DSA` (Digital Signature Algorithm), `ML-KEM` (Key Encapsulation Mechanism), `SLH-DSA`를 지원하여 양자 컴퓨팅 시대에 대응하는 보안 체계를 구축합니다.<br/>- 대칭키 암호: `ChaCha20-Poly1305` AEAD(Authenticated Encryption with Associated Data)를 지원하여 높은 수준의 기밀성과 무결성을 동시에 제공합니다.<br/>- 고성능 연산: 주요 알고리즘은 SIMD(Single Instruction, Multiple Data) 명령어 셋을 활용하여 병렬 처리를 극대화하고 연산 속도를 최적화합니다. |
| `certificate` | PQC 기반의 공개 키 인프라(PKI) 솔루션을 제공합니다.<br/>- PQC 키 쌍(`ML-DSA`, `SLH-DSA`)을 기반으로 `X.509` 표준 인증서를 생성, 서명, 검증하는 기능을 포함합니다.<br/>- `KeyStoreManager`를 통해 키 저장소를 안전하게 관리하며, 이를 활용하여 `SSL/TLS` 보안 채널을 구축하고 엔드투엔드 통신 암호화를 지원합니다.                                                                                                                                                                                                   |
| `exception`   | 안정적인 오류 처리를 위한 체계적인 예외 계층 구조를 제공합니다.<br/>- `EntLibSecurityException`, `EntLibAlgorithmSettingException` 등 예외 유형을 상세히 분류하여, 오류 발생 시 원인을 명확하게 식별하고 추적할 수 있도록 설계되었습니다.<br/>- 이를 통해 개발자는 견고하고 안정적인 애플리케이션을 구축할 수 있습니다.                                                                                                                                                                                                    |
| `util`        | 보안 및 개발 편의성을 고려한 고성능 유틸리티를 제공합니다.<br/>- `PemUtil`: `PEM` 형식의 키와 인증서를 인코딩/디코딩하는 기능을 제공합니다.<br/>- `SecureCharBuffer`: 암호나 키와 같은 민감한 문자열 데이터를 메모리상에서 안전하게 처리하고 명시적으로 해제하여 메모리 덤프 공격에 대응합니다.<br/>- `Hex`, `Hash` 등 데이터 처리에 필수적인 유틸리티를 포함합니다.                                                                                                                                                                              |
| `resource`    | 유연한 외부 리소스 관리 및 다국어(i18n) 지원 기능을 제공합니다.<br/>- `JSON` 및 `YAML` 형식의 외부 설정 파일을 안전하게 파싱하고 애플리케이션 구성에 반영합니다.<br/>- 표준화된 리소스 번들 제어(`ResourceBundle.Control`)를 통해 다국어 환경을 손쉽게 구축할 수 있는 인터페이스를 제공합니다.                                                                                                                                                                                                                         |

## 시작하기

### 1. 요구 사항

- Java 24 이상

얽힘 라이브러리는 NIST FIPS 203, 204, 205 표준화에 포함된 알고리즘을 안정적으로 사용하기 위해 Java 24 이상의 버전을 사용합니다.

### 2. 환경 변수 설정

`EntanglementLib`의 정상적인 동작을 위해 다음 환경 변수 설정이 필요합니다.

| 변수명                         | 설명                                     | 기본값     | 필수 여부 |
|-----------------------------|----------------------------------------|---------|-------|
| `ENTANGLEMENT_HOME_DIR`     | 라이브러리의 홈 디렉터리 경로를 지정합니다.               | -       | 필수    |
| `ENTANGLEMENT_PUBLIC_DIR`   | 공개 리소스가 저장될 디렉터리 경로를 지정합니다.            | -       | 필수    |
| `ENTANGLEMENT_DEFAULT_LANG` | 기본 언어 코드를 지정합니다. (예: `ko_KR`, `en_US`) | `ko_KR` | 선택    |

```bash
# 예시: Linux/macOS
export ENTANGLEMENT_HOME_DIR="/path/to/entanglement/home"
export ENTANGLEMENT_PUBLIC_DIR="/path/to/entanglement/public"

# 예시: Windows
setx ENTANGLEMENT_HOME_DIR "C:\path\to\entanglement\home"
setx ENTANGLEMENT_PUBLIC_DIR "C:\path\to\entanglement\public"
```

## TODO 및 기여

`EntanglementLib`는 팀 퀀트(Quant)에 속해 있습니다만, 기본적으로 원 개발자 `Q. T. Felix`에 의해 개발되어 해당 인원만이 독립적으로 관리됩니다.

이 프로젝트는 아직 많이 부족합니다. 얽힘 라이브러리는 미래에 금융 및 보안 인프라 프로덕션에서 사용할 수 있도록 다음의 TODO를 명확히 하고자 합니다.

- [ ] Java 모듈 시스템(JPMS)과 리플렉션의 충돌 문제 해결
  - `KeyDestroyHelper`에서 `Field.setAccessible(true)`를 사용하여 `BouncyCastle` 내부나 자바 표준 라이브러리의 `private` 필드를 수정하고 있습니다. Java 17 이후 강력한 캡슐화(strong encapsulation) 정책으로 인해, 실행 시 `--add-opens` JVM 옵션 없이는 `InaccessibleObjectException`이 발생할 확률이 매우 높습니다.
  - JVM 옵션 `--add-opens java.base/java.security=ALL-UNNAMED`를 추가하여 JPMS 보안 경고를 우회할 수 있습니다.
- [ ] 성능 대 보안 트레이드오프
  - 모든 입출력에 대해 방어적 복사(deep copy)를 수행하고 있습니다. 수 기가바이트 단위의 대용량 데이터를 처리하거나 높은 처리량(Tick Per Second, TPS)이 필요한 서버 환경에서는 잦은 메모리 할당과 가비지 컬렉터 부하로 성능 저하가 발생할 수 있습니다.
  - 기존 알고리즘 클래스는 상태를 가지기 때문에 이 문제가 돋보입니다. 이에 따라 얽힘 라이브러리 `1.1.0`부터 클래스가 상태를 가지지 않도록(stateless) 설계 방향을 굳힌 상태입니다.
- [ ] 난수 및 Nonce 관리
  - `ChaCha20Poly1305`에서 `InternalFactory.getSafeRandom()`을 사용해 논스값 `Nonce`를 생성합니다. 같은 키로 `Nonce`가 재사용되면 `ChaCha20Poly1305`의 보안성은 완전히 무너집니다.
- [ ] 공급자 유동화 및 팩토리 최적화
  - 사용자의 선택에 따라 Java의 기본 공급자를 사용할 수 있도록 수정해야 합니다. 그리고 `InternalFactory` 클래스를 포함한 대부분의 클래스에서 제공되는 팩토리를 최적화해야 합니다.

얽힘 라이브러리의 궁극적 양자-내성 보안을 완성시키기 위해 여러 개발자분들의 힘이 필요합니다. 언제든 코드에 대한 피드백을 남겨주세요. 퀀트에게 아주아주 큰 힘이 됩니다!

## 라이선스

본 프로젝트는 `PolyForm Noncommercial License 1.0.0`을 따릅니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참고하세요.

---

# 변경 사항

변경 사항은 [CHANGE.md](CHANGE) 문서에서 확인하실 수 있습니다.