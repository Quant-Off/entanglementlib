/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.tls.certificate;

import org.junit.jupiter.api.*;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.security.tls.certificate.KeyStoreManager;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.nio.file.Paths;

/**
 * 뭐하는 테스트 클래스임?
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
class CompositeTest {

    private static final char[] PASSWORD = "secret".toCharArray();

    @Test
    @DisplayName("")
    void test() throws Exception {
        KeyStoreManager keyStoreManager = new KeyStoreManager();
        keyStoreManager.loadKeyStore(Paths.get(InternalFactory.envEntanglementHomeDir(), "temp-keystore.bcfks"), PASSWORD.clone());
        keyStoreManager.loadTrustStore(Paths.get(InternalFactory.envEntanglementHomeDir(), "temp-truststore.bcfks"), PASSWORD.clone());

        SSLContext context = SSLContext.getInstance("TLSv1.3", InternalFactory._bcJSSEProvider);

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", InternalFactory._bcJSSEProvider);
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", InternalFactory._bcJSSEProvider);

        kmf.init(keyStoreManager.getKeyStore(), PASSWORD.clone());
        tmf.init(keyStoreManager.getTrustStore());

        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        System.out.println("SSLContext 작업: SSLContext 초기화 성공");
    }
  
}