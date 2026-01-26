# EF: BC Lightweight API and Strategy Pattern

이 패키지는 `BouncyCastle` 라이브러리의 저수준 API를 기반으로 한 몇 가지의 암호화 알고리즘과, `entlib-native`에서 연산이 이루어지는 전자 서명, 키 관리 기능 등을 제공하는 주력 암호화 모듈입니다.

저수준 API 기능은 `exp-bc-lightweight-api` 브랜치에서 우선 공개되지만, 네이티브 라이브러이 기능에 대해선 포함되지 않습니다. 어찌 뙜던 이 모든 기능은 `1.1.0` 릴리즈에 포함됩니다.

## 주요 기능

* 암호화 알고리즘 지원: AES, ARIA, ChaCha20 등 다양한 대칭 키 암호화 알고리즘을 지원합니다.
* 전자 서명 지원: RSA 및 FIPS 203, 204, 205 표준에 명시된 PQC(Post-Quantum Cryptography) 알고리즘을 지원합니다(단, FIPS 205 명세에 따른 `SLH-DSA` 알고리즘은 현재 개발 중에 있습니다).
* 확장 가능한 아키텍처: `AbstractStrategyBundle` 및 `EntLibCryptoRegistry`등의 팩토리 레지스트리를 통해 새로운 알고리즘을 쉽게 추가하고 관리할 수 있습니다.
* 안전한 민감 데이터 관리: `SensitiveDataContainer` 클래스를 통해 암호화 키의 생성, 저장, 폐기를 안전하게 처리합니다.

## 패키지 구조

### 핵심 인터페이스 및 클래스

* `EntLibAlgorithmType`: 모든 암호화 알고리즘 타입의 공통 인터페이스입니다. 카테고리, 패밀리, 키 크기, PQC 여부 등의 속성을 정의합니다.
* `EntLibCryptoCategory`: 암호화 알고리즘의 유형(CIPHER, SIGNATURE, KEY_AGREEMENT 등)을 분류하는 열거형입니다.
* `CryptoFamily`: 암호화 알고리즘의 패밀리(AES, RSA, ML_DSA 등)를 분류하는 열거형입니다.
* `EntLibCryptoRegistry`: 모든 암호화 스트레티지와 키 스트레티지를 관리하는 중앙 레지스트리입니다.
* `AbstractStrategyBundle`: 여러 스트레티지를 묶어서 레지스트리에 등록하는 번들 클래스의 기본 구현체입니다.
* `RegistrableStrategy`: 레지스트리에 등록 가능한 스트레티지 인터페이스입니다.

### 알고리즘 타입

* `CipherType`: 지원하는 암호화 알고리즘 목록
* `SignatureType`: 지원하는 전자 서명 알고리즘 목록 (ML-DSA, RSA 등)

### 키 관리 (key 패키지)

* `EntLibCryptoKey`: 네이티브 메모리(`Arena`, `MemorySegment`)를 사용하여 암호화 키를 안전하게 저장하고 관리하는 클래스입니다. `AutoCloseable`을 구현하여 사용 후
  자동으로 메모리를 소거(`wipe`)합니다. 현재 스레드 한정(`Arena.ofConfined`)으로 동작하므로 생성한 스레드에서만 접근 가능합니다.
* `KeyWiper`: 키 소거 작업을 수행하는 함수형 인터페이스입니다.
* `EntLibSymmetricKeyStrategy`: 대칭 키 생성 전략 인터페이스입니다. (`generateKey`)
* `EntLibAsymmetricKeyStrategy`: 비대칭 키 쌍 생성 전략 인터페이스입니다. (`generateKeyPair`)

### 스트레티지 (strategy 패키지)

* `EntLibCryptoStrategy`: 모든 암호화 스트레티지의 최상위 인터페이스입니다.
* `CipherStrategy`: 암호화/복호화 연산을 수행하는 인터페이스입니다. (`encrypt`, `decrypt`)
* `SignatureStrategy`: 전자 서명 및 검증을 수행하는 인터페이스입니다. (`sign`, `verify`)
* `BlockCipherStrategy`: 블록 암호화 전략 인터페이스입니다. 운영 모드(`Mode`), 패딩(`Padding`), 다이제스트(`Digest`) 설정 기능을 제공합니다.
* `StreamCipherStrategy`: 스트림 암호화 전략 인터페이스입니다. `ByteBuffer`를 이용한 스트리밍 암호화/복호화(`streamEncrypt`, `streamDecrypt`)를 지원합니다.
* `AEADCipherStrategy`: AEAD 암호화 전략 인터페이스입니다. AAD(`updateAAD`) 설정 기능을 제공합니다.

### 번들 (bundle 패키지)

* `AESStrategyBundle`: AES 암호화 스트레티지를 등록하는 번들입니다.
* `ARIAStrategyBundle`: ARIA 암호화 스트레티지를 등록하는 번들입니다.
* `ChaCha20StrategyBundle`: ChaCha20 암호화 스트레티지를 등록하는 번들입니다.
* `MLDSAStrategyBundle`: ML-DSA 서명 스트레티지를 등록하는 번들입니다.
* `SLHDSAStrategyBundle`: ML-DSA 서명 스트레티지를 등록하는 번들입니다.

### 상세 구현 (strategy.detail 패키지)

* `AbstractBlockCipher`: 블록 암호 알고리즘의 공통 기능을 제공하는 추상 클래스입니다. `BlockCipherStrategy`와 `AEADCipherStrategy`를 구현하며,
  BouncyCastle 엔진을 사용하여 실제 암호화/복호화를 수행합니다.
* `AbstractStreamCipher`: 스트림 암호 알고리즘의 공통 기능을 제공하는 추상 클래스입니다. `StreamCipherStrategy`를 구현합니다.
* `AESStrategy`: AES 알고리즘 구현체입니다. `AESEngine`을 사용하며, ECB 모드를 제외하고 IV를 자동으로 생성 및 관리합니다.
* `ARIAStrategy`: ARIA 알고리즘 구현체입니다. `ARIAEngine`을 사용하며, 대한민국 국가 표준 블록 암호입니다.
* `MLDSAStrategy`: ML-DSA PQC 서명 알고리즘 구현체입니다. `MLDSASigner`를 사용하여 서명 및 검증을 수행합니다.
* `ChaCha20Strategy`: ChaCha20 스트림 암호 구현체입니다. `ChaChaEngine`을 사용하며, 8바이트 Nonce(IV)를 사용합니다.
* `ChaCha20Poly1305Strategy`: ChaCha20-Poly1305 AEAD 암호 구현체입니다. 12바이트 Nonce(IV)와 16바이트 MAC을 사용하며, 스트리밍 암호화 시 청크 단위로
  처리합니다.

### 키 생성 전략 (key.strategy.detail 패키지)

* `AESSymmetricKeyStrategy`: AES 키 생성 전략입니다.
* `ARIASymmetricKeyStrategy`: ARIA 키 생성 전략입니다.
* `ChaCha20SymmetricKeyStrategy`: ChaCha20 키 생성 전략입니다.
* `ChaCha20Poly1305SymmetricKeyStrategy`: ChaCha20-Poly1305 키 생성 전략입니다.
* `MLDSAKeyStrategy`: ML-DSA 키 쌍 생성 전략입니다.
* `InternalKeyGenerator`: 내부적으로 사용되는 안전한 난수 기반 키 생성 유틸리티입니다.

## 사용 방법

### 1. 스트레티지 가져오기

`EntLibCryptoRegistry`를 통해 원하는 알고리즘의 스트레티지를 가져올 수 있습니다.

```java
// AES-256 암호화 스트레티지 가져오기
CipherStrategy aesStrategy = EntLibCryptoRegistry.getStrategy(CipherType.AES_256, CipherStrategy.class);

// ML-DSA-44 서명 스트레티지 가져오기
SignatureStrategy mldsaStrategy = EntLibCryptoRegistry.getStrategy(SignatureType.ML_DSA_44, SignatureStrategy.class);
```

### 2. 민감 데이터 관리

`SensitiveDataContainer`를 사용하여 민감 데이터를 네이티브 메모리에 안전하게 저장하고 관리합니다.
`close()` 호출 시 `entlib-native`를 통해 메모리가 완전히 소거됩니다.

```java
byte[] sensitiveData = ...; // 민감 데이터
// forceWipe=true: 원본 배열 즉시 소거 (소유권 이전)
try (SensitiveDataContainer container = new SensitiveDataContainer(sensitiveData, true)) {
    MemorySegment segment = container.getMemorySegment();
    // 데이터 사용
} // try 블록 종료 시 네이티브 메모리 자동 소거

// 암호학적으로 안전한 랜덤 바이트 생성
byte[] randomBytes = SensitiveDataContainer.generateSafeRandomBytes(32);
```

### 3. 새로운 알고리즘 추가

새로운 알고리즘을 추가하려면 다음 단계를 따르세요.

1. `AbstractStrategyBundle`을 상속받는 번들 클래스를 생성합니다.
2. `registerStrategies()` 메소드에서 해당 알고리즘의 스트레티지를 등록합니다.
3. `EntLibCryptoRegistry`의 static 블록에 새 번들의 인스턴스 참조를 추가하여 자동 등록되도록 합니다.

## 보안 고려사항

* `EntLibCryptoKey`는 `Arena.ofConfined()`를 사용하므로 생성된 스레드에서만 접근 가능합니다. 다른 스레드로 키를 전달하려면 `Arena.ofShared()`를 사용하는 방식으로 변경이
  필요할 수 있습니다.
* `EntLibCryptoKey.toByteArray()` 메소드는 힙 메모리에 키의 복사본을 생성합니다. 사용 후 반드시 `KeyDestroyHelper.zeroing()` 등을 사용하여 소거해야 합니다.