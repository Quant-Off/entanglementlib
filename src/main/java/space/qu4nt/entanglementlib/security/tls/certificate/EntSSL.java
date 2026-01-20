/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package space.qu4nt.entanglementlib.security.tls.certificate;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibSSLException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.util.security.Password;

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
    public SSLContext createSSLContext(final @NotNull String algorithm, final @Nullable String provider, final char @NotNull [] password) {
        if (context != null)
            return context;

        Objects.requireNonNull(keyStoreManager);

        try {
            // TLS 1.3 시도
            SSLContext context = createSSLContextWithProtocol(TLS_1_3, algorithm, provider, password);
            if (context != null) {
                this.context = context;
                log.info(lang.msg("ssl-context-created-tls13"));
                return context;
            }

            // TLS 1.3 실패 시 TLS 1.2 사용
            log.warn(lang.msg("tls13-not-available-fallback"));
            context = createSSLContextWithProtocol(TLS_1_2, algorithm, provider, password);
            if (context != null) {
                this.context = context;
                log.info(lang.msg("ssl-context-created-tls12"));
            }
            return this.context;
        } catch (Exception e) {
            throw new EntLibSSLException(EntSSL.class, "ssl-context-creation-failed-exc", e);
        }
    }

    // TODO 제거고려
    public SSLContext createSSLContext(final char @NotNull [] password) {
        return createSSLContext(PKIX, null, password);
    }

    private SSLContext createSSLContextWithProtocol(@NotNull String protocol, @NotNull String algorithm, @Nullable String provider, final char @NotNull [] keyPassword) {
        Objects.requireNonNull(protocol);
        Objects.requireNonNull(keyStoreManager);
        Objects.requireNonNull(algorithm);

        String fixProvider = provider == null ? InternalFactory.getBCJSSEProvider() : provider;
        try {
            SSLContext context = SSLContext.getInstance(protocol, fixProvider);

            // KeyManager 설정
            this.keyManagerFactory = KeyManagerFactory.getInstance(algorithm, fixProvider);
            keyManagerFactory.init(keyStoreManager.getKeyStore(), keyPassword);

            // TrustManager 설정 (인증서 검증 강화)
            this.trustManagerFactory = TrustManagerFactory.getInstance(algorithm, fixProvider);
            trustManagerFactory.init(keyStoreManager.getTrustStore());

            // SSLContext 초기화
            context.init(
                    keyManagerFactory.getKeyManagers(),
                    trustManagerFactory.getTrustManagers(),
                    InternalFactory.getSafeRandom()
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
