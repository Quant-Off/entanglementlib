/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.tls;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.security.tls.certificate.EntSSL;
import space.qu4nt.entanglementlib.security.tls.certificate.KeyStoreManager;
import space.qu4nt.entanglementlib.util.io.Password;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 서버 인증서를 사용하여 TLSv1.3 TCP 통신을 수행하기 위한 클래스입니다.
 * <p>
 * 이 클래스는 TLS 1.3 서버를 생성하고 실행하는 기능과,
 * 서버에 연결하기 위한 클라이언트 소켓을 생성하는 기능을 제공합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public class EntTCP {

    public static final Path KEYSTORE_PATH = Paths.get(InternalFactory.envEntanglementHomeDir(), "root", "temp-keystore.bcfks");
    public static final Path TRUSTSTORE_PATH = Paths.get(InternalFactory.envEntanglementHomeDir(), "root", "temp-truststore.bcfks");

    private final int port;
    @Getter
    private final EntSSL entSSL;

    private String[] sslParameterSignatureSchemes;
    private SSLServerSocket serverSocket;
    private ExecutorService executorService;
    private volatile boolean running = false;

    /**
     * EntTCP 서버를 생성합니다.
     *
     * @param password               키스토어 및 트러스트스토어에 사용할 문자 배열(비밀번호)
     * @param port                   서버 포트
     * @param serverPrivateKey       서버의 개인 키
     * @param serverCertificateChain 서버의 인증서 체인 (서버 인증서, ... , 루트 CA 인증서 순서)
     * @throws GeneralSecurityException 보안 관련 예외 발생 시
     * @throws IOException              I/O 오류 발생 시
     */
    public EntTCP(final char @NotNull [] password, int port, PrivateKey serverPrivateKey, X509Certificate... serverCertificateChain)
            throws GeneralSecurityException, IOException {
        this.port = port;

        KeyStoreManager keyStoreManager = new KeyStoreManager();
        try {
            // 인메모리 KeyStore, TrustStore 초기화
            keyStoreManager.loadKeyStore(KEYSTORE_PATH, password.clone());
            keyStoreManager.loadTrustStore(TRUSTSTORE_PATH, password.clone());

            // 서버 개인 키 및 인증서 체인 설정
            // setKeyEntry는 내부적으로 전달된 비밀번호 배열을 소거하므로 복제본을 전달
            keyStoreManager.setKeyEntry("server-alias", serverPrivateKey, password.clone(), serverCertificateChain);

            this.entSSL = new EntSSL(keyStoreManager);
        } finally {
            // 사용된 비밀번호 배열을 메모리에서 안전하게 소거
            Password.wipePassword(password);
        }
    }

    public void setDefaultAllSSLParameterSignatureSchemes() {
        this.sslParameterSignatureSchemes = new String[]{"rsa_pkcs1_sha1",
                "ecdsa_sha1",
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha384",
                "rsa_pkcs1_sha512",
                "ecdsa_secp256r1_sha256",
                "ecdsa_secp384r1_sha384",
                "ecdsa_secp521r1_sha512",
                "rsa_pss_rsae_sha256",
                "rsa_pss_rsae_sha384",
                "rsa_pss_rsae_sha512",
                "ed25519",
                "ed448",
                "rsa_pss_pss_sha256",
                "rsa_pss_pss_sha384",
                "rsa_pss_pss_sha512",
                "ecdsa_brainpoolP256r1tls13_sha256",
                "ecdsa_brainpoolP384r1tls13_sha384",
                "ecdsa_brainpoolP512r1tls13_sha512",
                "sm2sig_sm3",
                "mldsa44",
                "mldsa65",
                "mldsa87",
                "DRAFT_slhdsa_sha2_128s",
                "DRAFT_slhdsa_sha2_128f",
                "DRAFT_slhdsa_sha2_192s",
                "DRAFT_slhdsa_sha2_192f",
                "DRAFT_slhdsa_sha2_256s",
                "DRAFT_slhdsa_sha2_256f",
                "DRAFT_slhdsa_shake_128s",
                "DRAFT_slhdsa_shake_128f",
                "DRAFT_slhdsa_shake_192s",
                "DRAFT_slhdsa_shake_192f",
                "DRAFT_slhdsa_shake_256s"};
    }

    public void setSSLParameterSignatureSchemes(final @NotNull String... schemes) {
        this.sslParameterSignatureSchemes = schemes;
    }

    public void addSSLParameterSignatureScheme(final @NotNull String... schemes) {
        if (this.sslParameterSignatureSchemes == null) {
            this.sslParameterSignatureSchemes = schemes.clone();
            return;
        }
        final String[] news = new String[this.sslParameterSignatureSchemes.length + schemes.length];
        System.arraycopy(this.sslParameterSignatureSchemes, 0, news, 0, this.sslParameterSignatureSchemes.length);
        System.arraycopy(schemes, 0, news, this.sslParameterSignatureSchemes.length, schemes.length);
        this.sslParameterSignatureSchemes = news;
    }

    public @NotNull String[] getSSLParameterSignatureSchemes() {
        if (this.sslParameterSignatureSchemes == null) {
            setDefaultAllSSLParameterSignatureSchemes();
            return sslParameterSignatureSchemes;
        }
        return sslParameterSignatureSchemes;
    }

    /**
     * TLS 서버를 시작합니다.
     * 클라이언트 연결을 수락하고 각 연결을 별도의 스레드에서 처리합니다.
     *
     * @throws IOException 서버 소켓 생성 또는 바인딩 실패 시
     */
    public void start(final char @NotNull [] password) throws IOException {
        if (running) {
            log.info("Server is already running.");
            return;
        }

        final SSLContext sslContext = Objects.requireNonNull(entSSL).createSSLContext(password);

        // 파라미터 주입
        SSLParameters params = sslContext.getDefaultSSLParameters();
        params.setSignatureSchemes(getSSLParameterSignatureSchemes());

        final SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        this.serverSocket = (SSLServerSocket) ssf.createServerSocket(this.port);
        serverSocket.setSSLParameters(params);

        // 암호화 스위트 설정
        serverSocket.setEnabledCipherSuites(sslContext.getSocketFactory().getDefaultCipherSuites());

        this.executorService = Executors.newCachedThreadPool();
        this.running = true;
        log.info("EntTCP Server started on port {}", this.port);

        // 클라이언트 연결 수락 루프
        while (running) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                log.info("클라이언트 연결: {}", clientSocket.getRemoteSocketAddress());
                executorService.submit(() -> handleClient(clientSocket));
            } catch (IOException e) {
                if (!running) {
                    log.info("서버가 새 연결을 더 이상 받지 못했습니다.");
                } else {
                    log.error("클라이언트 연결 수락 오류", e);
                }
            }
        }

        Password.wipePassword(password);
    }

    /**
     * TLS 서버를 중지합니다.
     */
    public void stop() {
        this.running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            log.error("Error closing server socket: ", e);
        }
        if (executorService != null) {
            executorService.shutdownNow();
        }
        log.info("EntTCP Server has been stopped.");
    }

    /**
     * 클라이언트와의 통신을 처리합니다.
     * 현재는 받은 데이터를 그대로 다시 보내는 Echo 방식으로 구현되어 있습니다.
     *
     * @param clientSocket 클라이언트 소켓
     */
    private void handleClient(SSLSocket clientSocket) {
        try (clientSocket) {
            // 데이터 통신 로직 (Echo)
            java.io.InputStream input = clientSocket.getInputStream();
            if (input == null) {
                log.info("input is null EntTCP#handleClient");
                return;
            }
            java.io.OutputStream output = clientSocket.getOutputStream();
            if (output == null) {
                log.info("output is null EntTCP#handleClient");
                return;
            }
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
                output.flush();
            }
        } catch (IOException e) {
            // 클라이언트 연결 종료 또는 통신 오류
            log.info("Connection with client lost: {}", e.getMessage());
        } finally {
            log.info("Client disconnected: {}", clientSocket.getRemoteSocketAddress());
        }
    }

    /**
     * 지정된 호스트와 포트로 연결하는 TLS 클라이언트 소켓을 생성합니다.
     * 클라이언트는 제공된 CA 인증서를 신뢰하여 서버를 인증합니다.
     *
     * @param host          서버 호스트
     * @param port          서버 포트
     * @param trustedCaCert 신뢰할 루트 CA 인증서
     * @return 연결 및 핸드셰이크가 완료된 SSLSocket
     * @throws GeneralSecurityException 보안 관련 예외 발생 시
     * @throws IOException              I/O 오류 발생 시
     */
    public static SSLSocket createClientSocket(final char @NotNull [] password, String host, int port, X509Certificate trustedCaCert)
            throws GeneralSecurityException, IOException {

        // KeyStoreManager를 사용하여 신뢰할 인증서를 관리
        KeyStoreManager keyStoreManager = new KeyStoreManager();

        // 인메모리 TrustStore 초기화 (비밀번호 불필요)
        keyStoreManager.loadTrustStore(TRUSTSTORE_PATH, password.clone());
        keyStoreManager.setTruststoreCertificateEntry("ca-alias", trustedCaCert);

        // TrustManagerFactory 생성
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", InternalFactory._bcJSSEProvider);
        tmf.init(keyStoreManager.getTrustStore());

        // 클라이언트용 SSLContext 생성 및 초기화
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", InternalFactory._bcJSSEProvider);
        sslContext.init(null, tmf.getTrustManagers(), null);

        // SSLSocketFactory를 사용하여 소켓 생성 및 연결
        SSLParameters params = sslContext.getDefaultSSLParameters();
        params.setSignatureSchemes(new String[]{"mldsa87", "slhdsa_sha2_256s"});
        SSLSocketFactory sf = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) sf.createSocket(host, port);
        socket.setSSLParameters(params);

        // TLS 1.3만 사용하도록 설정
        socket.setEnabledProtocols(new String[]{"TLSv1.3"});

        // [핵심 수정] 클라이언트가 ML-DSA 서명을 지원함을 명시적으로 알려야 할 수 있음
        // BCJSSE 1.83은 자동 감지하지만, 아래 설정으로 강제하면 핸드셰이크 실패 확률이 줄어듭니다.
        SSLParameters sslParams = socket.getSSLParameters();

        // 필요 시 서명 알고리즘 확인 및 로깅 (디버깅용)
        // String[] sigSchemes = sslParams.getSignatureSchemes();
        // log.info("Supported Signatures: " + Arrays.toString(sigSchemes));
        socket.setSSLParameters(sslParams);

        // 핸드셰이크를 명시적으로 시작하여 연결을 즉시 확인
        socket.startHandshake();
        log.info("성공적 연결 " + host + ":" + port);

        return socket;
    }
}
