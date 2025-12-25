# EntanglementLib

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Quant-Off/entanglementlib)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-Java-orange.svg)](#)

얽힘 라이브러리(EntanglementLib) 는 양자 내성 암호(Post-Quantum Cryptography, PQC) 기술을 기반으로 설계된 고성능 보안 및 유틸리티 라이브러리입니다. 본 라이브러리는 진화하는 디지털 위협 환경에 대응하여 최고 수준의 보안과 시스템 안정성을 제공하는 것을 목표로 합니다.

## 핵심 철학

`EntanglementLib`의 모든 설계는 보안성(security) 을 최우선 원칙으로 합니다. 라이브러리는 잠재적 보안 취약점을 원천적으로 방지하고, 데이터 무결성을 보장하도록 구현되었습니다. 두 번째 핵심 가치는 안정성(stability) 으로, 예측 가능하고 일관된 성능을 보장하기 위해 메모리 효율성을 극대화하고 체계적인 오류 처리 메커니즘을 갖추었습니다.

## 주요 기능

`EntanglementLib`는 강력한 암호화 기능과 개발 생산성 향상을 위한 유틸리티를 포함합니다.

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

## 기여자

`EntanglementLib`는 팀 퀀트(Quant)에 의해 개발 및 관리되고 있습니다.

- 총괄: Q. T. Felix

## 라이선스

본 프로젝트는 Apache License 2.0을 따릅니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참고하세요.
