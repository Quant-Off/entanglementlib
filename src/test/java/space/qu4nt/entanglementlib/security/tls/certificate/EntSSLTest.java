/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.tls.certificate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.security.EntKeyPair;
import space.qu4nt.entanglementlib.security.algorithm.MLDSA;
import space.qu4nt.entanglementlib.security.algorithm.MLDSAType;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * {@link EntSSL}을 사용한 SSL 테스트 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
class EntSSLTest {

    private static final char[] PASS = "secret".toCharArray();

    private static final Path KEYSTORE_PATH = Paths.get(InternalFactory.envEntanglementHomeDir(), "root", "temp-keystore.bcfks");
    private static final Path TRUSTSTORE_PATH = Paths.get(InternalFactory.envEntanglementHomeDir(), "root", "temp-truststore.bcfks");

    @Test
    @DisplayName("루트, 서버 인증서 저장 및 로컬 TLS")
    void justCreateStoresTest() {
        try (MLDSA rootMLDSA = MLDSA.create(MLDSAType.ML_DSA_87, "root")) {
            EntKeyPair rootPair = rootMLDSA.generateEntKeyPair();
            final X509Certificate rootCert = Certificator.generateRootCACertificate(
                    rootMLDSA.getType(),
                    rootPair.keyPair().getPublic(),
                    rootPair.keyPair().getPrivate(),
                    Certificator.DEFAULT_ROOT_CA_QCR3_TBS);

            KeyStoreManager keyStoreManager = new KeyStoreManager();
            keyStoreManager.loadKeyStore(KEYSTORE_PATH, PASS.clone());
            keyStoreManager.loadTrustStore(TRUSTSTORE_PATH, PASS.clone());

            keyStoreManager.setTruststoreCertificateEntry("root-ca-cert", rootCert);

            keyStoreManager.setKeyEntry("root-ca-cert-and-keypair", rootPair.keyPair().getPrivate(), PASS.clone(), new Certificate[]{rootCert});

            try (MLDSA serverMLDSA = MLDSA.create(MLDSAType.ML_DSA_87, "server")) {
                EntKeyPair serverPair = serverMLDSA.generateEntKeyPair();
                X509Certificate serverCert = Certificator.generateCAChainCertificate(
                        Certificator.DEFAULT_ROOT_CA_QCR3_TBS,
                        Certificator.DEFAULT_SERVER_RiS_TBS,
                        rootMLDSA.getType(),
                        serverPair.keyPair().getPublic(),
                        rootPair.keyPair().getPrivate());

                keyStoreManager.setKeyEntry("server-cert-and-keypair", serverPair.keyPair().getPrivate(), PASS.clone(), new Certificate[]{serverCert});
                System.out.println("서버 인증서, 비밀 키 키스토어에 저장 완료");

                keyStoreManager.storeKeyStore(PASS.clone());
                keyStoreManager.storeTrustStore(PASS.clone());
                System.out.println("키, 트서스트스토어 최종 저장 완료");

                // SSL
                EntSSL ssl = new EntSSL(keyStoreManager);
                // server
                final SSLContext serverContext = ssl.createSSLContext(PASS.clone());
                // client
                final SSLContext clientContext = ssl.createSSLContext(PASS.clone());

                try (ExecutorService service = Executors.newSingleThreadExecutor()) {
                    service.submit(() -> startServer(serverContext, 8443));

                    Thread.sleep(1500); // 1.5s wait

                    connectClient(clientContext, "localhost", 8443);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void startServer(SSLContext context, int port) {
        SSLParameters serverParams = context.getDefaultSSLParameters();
        serverParams.setSignatureSchemes(new String[]{"mldsa87"});
//        serverParams.setNamedGroups(new String[]{"X25519MLKEM768", "x25519"});
        SSLServerSocketFactory serverSocketFactory = context.getServerSocketFactory();
        try (SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(8443)) {
            serverSocket.setSSLParameters(serverParams);
            System.out.println("[서버] " + port + " 포트에서 대기");
            serverSocket.setEnabledCipherSuites(context.getSocketFactory().getDefaultCipherSuites());
            try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept()) {
                clientSocket.startHandshake();

                var in = clientSocket.getInputStream();
                var out = clientSocket.getOutputStream();

                byte[] buf = new byte[1024];
                int read = in.read(buf);
                String received = new String(buf, 0, read);
                System.out.println("[서버] 수신: " + received);

                out.write("Echo".getBytes());
                out.write(buf, 0, read);
                out.flush();
            }
            System.out.println("[서버] 핸드셰이크 성공");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void connectClient(SSLContext context, String host, int port) throws IOException {
        SSLParameters clientParams = context.getDefaultSSLParameters();
        clientParams.setSignatureSchemes(new String[]{"mldsa87"});
//        clientParams.setNamedGroups(new String[]{"X25519MLKEM768", "x25519"});
        SSLSocketFactory clientSocketFactory = context.getSocketFactory();
        try (SSLSocket clientSocket = (SSLSocket) clientSocketFactory.createSocket(host, port)) {
            clientSocket.setSSLParameters(clientParams);
            clientSocket.startHandshake();  // Initiates the TLS handshake
            System.out.println("[클라이언트] 연결됨: " + host + ":" + port);
            System.out.println("[클라이언트] 핸드셰이크 성공]");

            var out = clientSocket.getOutputStream();
            var in = clientSocket.getInputStream();

            String message = "Hello, Quantum World!";
            out.write(message.getBytes());
            out.flush();

            byte[] buf = new byte[1024];
            int read = in.read(buf);
            String response = new String(buf, 0, read);
            System.out.println("[클라이언트] 서버 응답: " + response);
        }
    }

}