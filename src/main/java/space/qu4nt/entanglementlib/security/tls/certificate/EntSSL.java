/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.tls.certificate;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibSSLException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.util.io.Password;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.*;
import java.util.Objects;

/**
 * SSL 제어하는 클래스
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
@Getter
public class EntSSL {

    private static final LanguageInstanceBased<EntSSL> lang = LanguageInstanceBased.create(EntSSL.class);

    private static final String TLS_1_3 = "TLSv1.3";
    private static final String TLS_1_2 = "TLSv1.2";
    private static final String PKIX = "PKIX";

    private final KeyStoreManager keyStoreManager;

    private KeyManagerFactory keyManagerFactory;
    private TrustManagerFactory trustManagerFactory;

    private SSLContext context;

    /**
     * {@link EntSSL} 인스턴스를 생성합니다.
     *
     * @param keyStoreManager 키스토어 매니저 인스턴스
     * @throws NullPointerException 인자가 {@code null}인 경우
     */
    public EntSSL(@NotNull KeyStoreManager keyStoreManager) {
        this.keyStoreManager = Objects.requireNonNull(keyStoreManager);
    }

    @NotNull
    public SSLContext createSSLContext(final char @NotNull [] password) {
        if (context != null)
            return context;

        Objects.requireNonNull(keyStoreManager);

        try {
            // TLS 1.3 시도
            SSLContext context = createSSLContextWithProtocol(TLS_1_3, password);
            if (context != null) {
                this.context = context;
                log.info(lang.msg("ssl-context-created-tls13"));
                return context;
            }

            // TLS 1.3 실패 시 TLS 1.2 사용
            log.warn(lang.msg("tls13-not-available-fallback"));
            context = createSSLContextWithProtocol(TLS_1_2, password);
            if (context != null) {
                this.context = context;
                log.info(lang.msg("ssl-context-created-tls12"));
            }
            return this.context;
        } catch (Exception e) {
            throw new EntLibSSLException(EntSSL.class, "ssl-context-creation-failed-exc", e);
        }
    }

    private SSLContext createSSLContextWithProtocol(@NotNull String protocol, final char @NotNull [] keyPassword) {
        Objects.requireNonNull(keyStoreManager);
        try {
            SSLContext context = SSLContext.getInstance(protocol, InternalFactory._bcJSSEProvider);

            // KeyManager 설정
            this.keyManagerFactory = KeyManagerFactory.getInstance(PKIX, InternalFactory._bcJSSEProvider);
            keyManagerFactory.init(keyStoreManager.getKeyStore(), keyPassword);

            // TrustManager 설정 (인증서 검증 강화)
            this.trustManagerFactory = TrustManagerFactory.getInstance(PKIX, InternalFactory._bcJSSEProvider);
            trustManagerFactory.init(keyStoreManager.getTrustStore());

            // SSLContext 초기화
            context.init(
                    keyManagerFactory.getKeyManagers(),
                    trustManagerFactory.getTrustManagers(),
                    InternalFactory.SAFE_RANDOM
            );
            return context;
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException |
                 KeyManagementException e) {
            log.error(lang.args("ssl-context-creation-exc", protocol), e);
            return null;
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } finally {
            Password.wipePassword(keyPassword);
        }
    }
}
