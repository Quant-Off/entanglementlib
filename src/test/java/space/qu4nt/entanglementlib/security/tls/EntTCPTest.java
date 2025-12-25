/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.tls;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.slf4j.bridge.SLF4JBridgeHandler;
import space.qu4nt.entanglementlib.security.algorithm.MLDSA;
import space.qu4nt.entanglementlib.security.algorithm.MLDSAType;
import space.qu4nt.entanglementlib.security.algorithm.SLHDSA;
import space.qu4nt.entanglementlib.security.algorithm.SLHDSAType;
import space.qu4nt.entanglementlib.security.tls.certificate.Certificator;
import space.qu4nt.entanglementlib.util.io.Password;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link EntTCP} 테스트 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EntTCPTest {

    private X509Certificate rootCACert;
    private X509Certificate serverCert;
    private KeyPair serverPair;
    private SLHDSA slhdsa;
    private MLDSA mldsa;
    private static final int TEST_PORT = 8443;
    private static final char[] password = Password.generate();

    @BeforeAll
    void setUp() throws Exception {
        // 기존 JUL 핸들러 제거 (중복 출력 방지)
        SLF4JBridgeHandler.removeHandlersForRootLogger();

        // JUL -> SLF4J 브릿지 설치
        SLF4JBridgeHandler.install();

        // JUL의 "org.bouncycastle" 로거 레벨을 FINEST로 강제 설정
        // 주의: 이 설정이 없으면 JUL 자체가 INFO 레벨에서 차단하여 SLF4J로 넘어가지 않음
        Logger bcLogger = Logger.getLogger("org.bouncycastle");
        bcLogger.setLevel(Level.FINEST);


        // --- 인증서 및 키 페어 생성 ---
        slhdsa = SLHDSA.create(SLHDSAType.SLH_DSA_SHA2_256s, "root");
        final KeyPair rootPair = slhdsa.generateEntKeyPair().keyPair();
        rootCACert = Certificator.generateRootCACertificate(
                slhdsa.getType(),
                rootPair.getPublic(),
                rootPair.getPrivate(),
                Certificator.DEFAULT_ROOT_CA_QCR3_TBS
        );

        mldsa = MLDSA.create(MLDSAType.ML_DSA_87, "server");
        serverPair = mldsa.generateEntKeyPair().keyPair();
        serverCert = Certificator.generateCAChainCertificate(
                Certificator.DEFAULT_ROOT_CA_QCR3_TBS,
                Certificator.DEFAULT_SERVER_RiS_TBS,
                slhdsa.getType(),
                serverPair.getPublic(),
                rootPair.getPrivate()
        );

        Objects.requireNonNull(rootCACert, "Root CA cert");
        Objects.requireNonNull(serverCert, "Server cert");
        log.info("테스트용 인증서와 키 페어 생성");
    }

    @AfterAll
    void tearDown() {
        if (slhdsa != null) slhdsa.close();
        if (mldsa != null) mldsa.close();
        log.info("암호화 리소스가 닫혔습니다.");
    }

    @Test
    @Order(1)
    @DisplayName("EntTCP 서버 시작 및 종료 테스트")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void serverStartAndStopTest() {
        assertDoesNotThrow(() -> {
            EntTCP server = new EntTCP(password.clone(), TEST_PORT, serverPair.getPrivate(), serverCert, rootCACert);
            ExecutorService executor = Executors.newSingleThreadExecutor();
            executor.submit(() -> {
                try {
                    server.start(password.clone());
                } catch (IOException _) {
                }
            });
            Thread.sleep(200);

            server.stop();
            executor.shutdownNow();
            executor.close();
            assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS), "Executor 는 터미네이트 되어야합니다");
            log.info("서버 시작 및 종료 테스트가 성공적으로 완료되었습니다.");
        });
    }

    @Test
    @Order(2)
    @DisplayName("TLSv1.3 Echo 통신 테스트")
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    void fullCommunicationTest() throws Exception {
        final EntTCP server = new EntTCP(password.clone(), TEST_PORT, serverPair.getPrivate(), serverCert, rootCACert);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            // 서버를 백그라운드 스레드에서 시작
            executor.submit(() -> {
                try {
                    server.start(password.clone());
                } catch (IOException e) {
                    // 서버가 stop()에 의해 정상적으로 닫힐 때 발생하는 예외는 무시
                    if (e.getMessage().contains("Socket closed")) {
                        log.info("서버 소켓이 예상대로 닫혔습니다.");
                    } else {
                        fail("서버 시작 실패", e);
                    }
                }
            });

            // 서버가 포트를 열 충분한 시간을 기다림
            Thread.sleep(1000);

            // 클라이언트 연결 및 Echo 테스트 수행
            performClientEchoTest();

        } finally {
            // 테스트 종료 시 서버와 스레드 풀을 확실히 종료
            server.stop();
            executor.shutdownNow();
            executor.close();
            if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                log.warn("Executor 가 제때 종료되지 않음");
            }
            log.info("전체 통신 테스트 완료, 서버와 Executor 종료");
        }
    }

    private void performClientEchoTest() {
        log.info("클라이언트와 연결 시도 중...");
        try (SSLSocket clientSocket = EntTCP.createClientSocket(password.clone(), "localhost", TEST_PORT, rootCACert)) {
            assertNotNull(clientSocket, "clientSocket");
            assertTrue(clientSocket.isConnected(), "클라이언트는 연결되어 있어야 합니다!");
            log.info("클라이언트가 성공적으로 연결되었습니다.");

            OutputStream out = clientSocket.getOutputStream();
            InputStream in = clientSocket.getInputStream();

            String testMessage = "Hello, EntanglementLib! This is an echo test.";
            byte[] messageBytes = testMessage.getBytes();

            log.info("[클라이언트 전송]: {}", testMessage);
            out.write(messageBytes);
            out.flush();

            byte[] buffer = new byte[4096];
            int bytesRead = in.read(buffer);
            assertTrue(bytesRead > 0, "서버가 데이터를 수신받아야 합니다!");

            String receivedMessage = new String(buffer, 0, bytesRead);
            log.info("[서버 수신]: {}", receivedMessage);

            assertEquals(testMessage, receivedMessage, "송수신 메시지는 동일해야 합니다!");

        } catch (GeneralSecurityException | IOException e) {
            fail("예외와 함께 클라이언트 통신 실패", e);
        }
    }
}
