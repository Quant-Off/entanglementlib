# EF: X25519 and ML-KEM-768 Hybrid

이제 얽힘 라이브러리 `1.1.0` 릴리즈부턴 하이브리드 알고리즘을 지원합니다. 예를 들어,
타원곡선 디피-헬만(ECDH) `Curve25519` 알고리즘과 양자-내성 키 캡슐화 메커니즘인 `ML-KEM-768` 알고리즘을 조합한 `X25519MLKEM768`이 주력입니다.

이 알고리즘은 `securiry/crypto/strategy/detail/hybrid` 패키지에 포함됩니다. 다른 알고리즘을 레지스트리에서 호출하여 사용할 수 있듯이 해당 알고리즘도 동일하게 사용할 수 있습니다.
다만 다른 알고리즘 호출에 비해 한 가지 기술적인 차이점이 존재합니다.

## 사용

`X25519MLKEM768` 알고리즘은 레지스트리로부터 다음과 같이 호출할 수 있습니다.

```java
void main() {
    // 알고리즘 키 스트레티지
    final X25519MLKEM768KeyStrategy keyStrategy =
            EntLibCryptoRegistry.getKeyStrategy(KEMType.X25519MLKEM768, X25519MLKEM768KeyStrategy.class);

    // 알고리즘 수행 스트레티지
    final X25519MLKEM768Strategy strategy = EntLibCryptoRegistry.getAlgStrategy(KEMType.X25519MLKEM768, X25519MLKEM768Strategy.class);
}
```

다른 알고리즘 클래스와는 다르게 하위 구현부 클래스를 직접 가져와야 합니다. 구현부 클래스에서 사용 가능한 메소드가 있기 때문입니다.

`X25519MLKEM768` 스트레티지 클래스는 모두 자식 레벨에서 할당해주어야 하는 다음의 필드 두 가지가 공통적으로 존재합니다.

- `MLKEMStrategy` 및 `MLKEMKeyStrategy`
- `X25519Strategy` 및 `X25519KeyStrategy`

이유는 간단합니다. 해당 알고리즘은 위 두 알고리즘의 하이브리드 알고리즘이기 때문입니다. `X25519MLKEM768` 알고리즘 클래스들을 호출하는 시점에 개별 알고리즘 클래스(X25519, MLKEM)를 생성하게
되면 세션이 같아도 유효한 디캡슐화(decapsulate) 결과를 얻을 수 없습니다. 이 문제를 해결하기 위해 자식 레벨에서 위 두 개별 알고리즘에 대한 스트레티지를 등록하도록 설계했습니다. 위 코드는 다음과 같이
수정 가능합니다.

```java
void main() {
    // 알고리즘 키 스트레티지
    final X25519MLKEM768KeyStrategy keyStrategy =
            EntLibCryptoRegistry.getKeyStrategy(KEMType.X25519MLKEM768, X25519MLKEM768KeyStrategy.class);
    strategy.setX25519Strategy((X25519Strategy) x25519Strategy);
    strategy.setMlkemStrategy((MLKEMStrategy) mlkem768Strategy);

    // 알고리즘 수행 스트레티지
    final X25519MLKEM768Strategy strategy = EntLibCryptoRegistry.getAlgStrategy(KEMType.X25519MLKEM768, X25519MLKEM768Strategy.class);
    ecdhePairStrategy.setX25519Key((X25519KeyStrategy) x25519KeyStrategy);
    ecdhePairStrategy.setMlkem768Key((MLKEMKeyStrategy) mlkem768KeyStrategy);
}
```

말인 즉슨, 사전에 `X25519`, `ML-Kem-768` 알고리즘에 대한 스트레티지를 생성해두어야 한다는 것입니다. 

객체를 생성하고 나서는 그저 캡슐화와 디캡슐화 메소드를 사용하여 작업을 수행하면 됩니다.

