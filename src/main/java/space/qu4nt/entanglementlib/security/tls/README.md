# EntLib: 통신

TCP는 신뢰성 있는 데이터 전송을 담당하는 **전송 계층 프로토콜**이고, TLS는 그 위에 올라가 **데이터를 암호화하여 보안을 제공하는 프로토콜**로, TCP를 통해 안전한 통신 채널을 만드는 역할을 합니다.

서버와 클라이언트의 `SSLContext`는 명확히 다릅니다. 클라이언트가 크롬(Chrome) 브라우저를 사용한다고 했을 때, 다음의 과정을 거칩니다.

1. 준비 (Application Start)
    - 브라우저가 실행될 때 이미 내부적으로 `Default SSLContext`가 만들어집니다. 이 안에는 우리가 신뢰하는 인증 기관(Root CA) 목록이 미리 들어 있습니다. 예를 들어 `DigiCert`,
      `Let's Encrypt` 등이 있습니다.
    - Java의 경우: `$JAVA_HOME/lib/security/cacerts` 파일에 있는 인증서들을 로딩합니다.
2. 연결 시도 (Handshake)
    - 사용자가 구글에 접속하는 경우 URL `https://google.com`을 입력하고 엔터를 칩니다. 클라이언트는 구글 서버에 `ClientHello` 메시지를 보냅니다(아직 HTTP 요청을 보내는 게
      아님, 인사만 함).
3. 검증 (Verification)
    - 구글 서버가 자신의 인증서(Certificate)를 클라이언트에게 보냅니다. 이때 클라이언트는 1단계에서 미리 만들어둔 SSLContext(TrustStore)를 꺼내서 확인합니다.
    - "이 구글 인증서가 내가 미리 가지고 있는 신뢰 목록(Root CA)에 의해 서명된 게 맞는가?"를 확인합니다.
4. 통신 시작 (HTTP Request)
    - 검증이 통과되면 그제서야 암호화 채널이 열리고, 실제 `GET /search...` 같은 데이터 요청을 보냅니다.

하지만 얽힘 라이브러리는 TCP 통신을 위해 양자-내성 암호화를 사용하여 TLS1.3 및 TLS1.2 프로토콜을 생성할 수 있으며, 이 기술(양자-내성 암호화 알고리즘)은 아직 완전히 상용화되지 않아 대부분 브라우저
및 웹 서버에선 지원하지 않습니다. 즉, 서버가 `SLH-DSA` 알고리즘을 통해 루트 인증서를 발급해도 브라우저는 알지 못하기 때문에 클라이언트는 이 사실을 브라우저에게 알리기 위해 브라우저에 서버로부터 받은
인증서(루트 인증서에 서명된 인증서)를 등록해주어야 할 수 있습니다.

쉽게 말해 사용자가 양자-내성 암호화 연결을 사용하는 웹 서버를 오픈한 경우 접속하는 클라이언트는 양자-내성 암호화 알고리즘으로 서명된 인증서를 가지고 있어야 합니다.

# 로직 설명

이 설명은 이 패키지(`tls`) 내에 존재하는 객체만들 취급함을 명심하세요.

## 키스토어 관리

키스토어, 트러스트스토어 관리를 수월하게 하려면 `tls.certificate.KeyStoreManager.java` 클래스를 활용할 수 있습니다.

```java
import space.qu4nt.entanglementlib.security.tls.certificate.KeyStoreManager;
import space.qu4nt.entanglementlib.util.security.Password;

class Main {
   public static void main(String[] args) {
      // 매니저 선언
      KeyStoreManager keyStoreManager = new KeyStoreManager();

      // 키스토어 비밀번호 설정 (Password 객체를 사용하여 안전한 비밀번호 생성)
      final char[] pass = Password.generate();

      // 키스토어 로드 (내부적으로 비밀번호가 소거되기 때문에 복사본 전달)
      keyStoreManager.loadKeyStore(keyStorePath, pass.clone());

      // 트러스트스토어 로드
      keyStoreManager.loadTrustStore(TrustStorePath, pass.clone());
   }
}
```

위 과정을 거치면 할당된 경로에 키스토어, 트러스트스토어 파일을 로드합니다. 파일이 존재하지 않는 경우 빈 스토어를 생성합니다. `KeyStoreManager#setKeyEntry(...)` 등의 메소드를 사용하여
키스토어에 엔트리를 추가하거나 인증서 체인을 추가한 뒤 다음 메소드를 통해 지정된 경로에 저장할 수 있습니다.

```java
class Main {
    public static void main(String[] args) {
        final char[] pass = Password.generate();

        KeyStoreManager keyStoreManager = new KeyStoreManager();
        // ... 키스토어 매니지먼트 로직

        // 키스토어 저장
        keyStoreManager.storeKeyStore(pass.clone());

        // 트러스트스토어 저장
        keyStoreManager.storeTrustStore(pass.clone());
    }
}
```

또한 `isTrusted(@NotNull X509Certificate certificate)` 메소드를 통해 전달받은 인증서 객체가 트러스트스토어에서 신뢰할 수 있는 인증서인지 검증할 수 있습니다. 반환 결과는
`boolean`입니다.

## SSLContext 생성

`SSLContext` 객체를 생성하기 위해 `tls.certificate.EntSSL.java` 클래스를 사용할 수 있습니다. 클래스 메소드에 매개변수로
`tls.certificate.KeyStoreManager.java` 클래스를 전달해야 합니다.

```java
import space.qu4nt.entanglementlib.security.tls.certificate.EntSSL;
import space.qu4nt.entanglementlib.security.tls.certificate.KeyStoreManager;
import space.qu4nt.entanglementlib.util.security.Password;

import javax.net.ssl.SSLContext;

class Main {
   public static void main(String[] args) {
      final char[] pass = Password.generate();

      KeyStoreManager keyStoreManager = new KeyStoreManager();
      // ... 키스토어 매니지먼트 로직

      // 객체 선언
      EntSSL entSSL = new EntSSL(keyStoreManager);

      // SSLContext 생성 (내부적으로 비밀번호가 소거되기 때문에 복사본 전달)
      SSLContext context = entSSL.createSSLContext(pass.clone());
   }
}
```

`createSSLContext` 메소드는 기본적으로 TLS1.3을 통해 `SSLContext`를 생성하려고 시도합니다. 만약 생성에 실패한다면 TLS1.2를 사용하고, 이 마저도 실패 시 Runtime 예외를
발생시켜 애플리케이션을 종료합니다. TLS1.1은 보안상 얽힘 라이브러리에서 사용할 수 없습니다.

## TCP 서버 생성

`tls.EntTCP.java` 클래스를 사용하여 간편하게 TCP 서버를 생성할 수 있습니다. 이 클래스는 선언 시 포트와 서버의 비밀 키, 인증서 체인을 전달받으며 내부적으로 `KeyStoreManager`,
`SSLContext`객체를 생성하고 전역 변수에 할당합니다.

사용자가 `ML-DSA` 알고리즘의 `65` 파라미터를 사용하여 TCP서버를 열고자 하는 경우 다음과 같이 할 수 있습니다.

```java
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.algorithm.MLDSA;
import space.qu4nt.entanglementlib.security.algorithm.MLDSAType;
import space.qu4nt.entanglementlib.security.tls.EntTCP;

import java.security.cert.X509Certificate;

class Main {
   public static void main(String[] args) {
      // 서버 오픈에 사용될 객체
      MLDSA mldsa = MLDSA.create(MLDSAType.ML_DSA_65, "server");
      EntLibKeyPair serverPair = mldsa.generateEntKeyPair();

      // 루트 CA 인증서 생성
      X509Certificate rootCert = ...;
      // 루트 인증서의 주체 정보를 사용해 서버 인증서 생성
      X509Certificate serverCert = ...;

      // 갹체 선언
      EntTCP server = new EntTCP(8443, PrivateKey, rootCert, serverCert);
      // ... 서버 상호작용 ...

      // 서버 종료
      server.stop();
      mldsa.close(); // 모든 정보 소거
   }
}
```

## 인증서 생성

인증서 및 인증서 체인을 생성하기 위해 `tls.certificate.Certificator.java` 클래스를 사용할 수 있습니다.

먼저 인증서 발급 대상의 정보를 담은 `SubjectString` 객체를 생성하고, `Certificator`의 정적 메소드를 호출하여 인증서를 생성합니다.

```java
import space.qu4nt.entanglementlib.security.EntLibKeyPair;
import space.qu4nt.entanglementlib.security.algorithm.MLDSA;
import space.qu4nt.entanglementlib.security.algorithm.MLDSAType;
import space.qu4nt.entanglementlib.security.tls.certificate.Certificator;
import space.qu4nt.entanglementlib.security.tls.certificate.SubjectString;

import java.security.cert.X509Certificate;

class Main {
   public static void main(String[] args) {
      // 1. 키 쌍 생성
      MLDSA rootMldsa = MLDSA.create(MLDSAType.ML_DSA_65, "root");
      EntLibKeyPair rootPair = rootMldsa.generateEntKeyPair();

      MLDSA serverMldsa = MLDSA.create(MLDSAType.ML_DSA_65, "server");
      EntLibKeyPair serverPair = serverMldsa.generateEntKeyPair();

      // 2. 주체 정보(SubjectString) 생성
      SubjectString rootSubject = SubjectString.builder()
              .commonName("Root CA")
              .organization("Org")
              .country("KR")
              .build();

      SubjectString serverSubject = SubjectString.builder()
              .commonName("Server")
              .organization("Org")
              .country("KR")
              .build();

      try {
         // 3. 루트 CA 인증서 생성 (자체 서명)
         X509Certificate rootCert = Certificator.generateRootCACertificate(
                 MLDSAType.ML_DSA_65,      // 알고리즘 사양
                 rootPair.getPublic(),     // 루트 공개 키
                 rootPair.getPrivate(),    // 루트 비밀 키
                 rootSubject               // 루트 주체 정보
         );

         // 4. 서버 인증서 생성 (루트 CA로 서명)
         X509Certificate serverCert = Certificator.generateCAChainCertificate(
                 rootSubject,              // 발급자(Issuer) 정보
                 serverSubject,            // 주체(Subject) 정보
                 MLDSAType.ML_DSA_65,      // 알고리즘 사양
                 serverPair.getPublic(),   // 서버 공개 키
                 rootPair.getPrivate()     // 루트 비밀 키 (서명용)
         );
      } catch (Exception e) {
         // 예외 핸들링
      } finally {
         // 모든 정보 소거
         rootMldsa.close();
         serverMldsa.close();
      }
   }
}
```

# 실제 사용

실제 사용을 위해 클라이언트 코드는 크게 다음 순서를 따라야 합니다.

1. `SSLContext` 생성
   - 앱이 켜질 때, 혹은 통신 직전에 수행 
   - TrustStore 로딩
2. `SSLSocketFactory` 추출 
   - 생성된 `SSLContext`에서 소켓 팩토리 호출
3. socket.connect()
   - 서버에 접속을 시도

이 과정이 정상적으로 수행되면 클라이언트는 서버에 접속할 수 있고, 요청 및 응답을 주고받을 수 있습니다.