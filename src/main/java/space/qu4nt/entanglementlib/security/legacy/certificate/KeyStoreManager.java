/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.legacy.certificate;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureJCAJCEStoreProcessException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Objects;

/**
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public class KeyStoreManager {

    private static final LanguageInstanceBased<KeyStoreManager> lang =
            LanguageInstanceBased.create(KeyStoreManager.class);

    public static final String PKCS12 = "PKCS12";
    public static final String JKS = "JKS"; // legacy support
    public static final String BCFKS = "BCFKS";

    private static final String DEFAULT_KEYSTORE_TYPE = BCFKS;

    @Getter
    private final KeyStore keyStore;
    @Getter
    private final KeyStore trustStore;
    @Getter
    private final String keyStoreType;

    private Path keyStorePath;
    private Path trustStorePath;

    /**
     * 기본 BCFKS 타입의 키스토어 매니저를 생성합니다.
     */
    public KeyStoreManager() throws EntLibSecureJCAJCEStoreProcessException {
        this(DEFAULT_KEYSTORE_TYPE);
    }

    /**
     * 지정된 타입의 키스토어 매니저를 생성합니다.
     *
     * @param keyStoreType 키스토어 타입 (BCFKS, PKCS12 등)
     */
    public KeyStoreManager(@NotNull String keyStoreType) throws EntLibSecureJCAJCEStoreProcessException {
        this(keyStoreType, InternalFactory.getBCNormalProvider());
    }

    public KeyStoreManager(@NotNull String keyStoreType, final @Nullable String provider)
            throws EntLibSecureJCAJCEStoreProcessException {
        this.keyStoreType = Objects.requireNonNull(keyStoreType);
        try {
            if (provider == null) {
                this.keyStore = KeyStore.getInstance(keyStoreType);
                this.trustStore = KeyStore.getInstance(keyStoreType);
            } else {
                this.keyStore = KeyStore.getInstance(keyStoreType, provider);
                this.trustStore = KeyStore.getInstance(keyStoreType, provider);
            }
        } catch (KeyStoreException | NoSuchProviderException e) {
            log.error(lang.thr("failed-keystore-init-exc", e, keyStoreType));
            throw new EntLibSecureJCAJCEStoreProcessException(KeyStoreManager.class, "failed-keystore-init-err-exc", e);
        }
    }

    /**
     * 키스토어를 파일에서 로드합니다.
     * <p>
     * 비밀번호 배열은 복사본이 전달되어도 사용 후 즉시 영소거됩니다.
     *
     * @param keyStorePath 키스토어 파일 경로
     * @param password     키스토어 비밀번호
     */
    public void loadKeyStore(@NotNull Path keyStorePath, char @NotNull [] password)
            throws IOException, CertificateException, NoSuchAlgorithmException, EntLibSecureJCAJCEStoreProcessException {
        Objects.requireNonNull(keyStorePath);
        Objects.requireNonNull(password);

        this.keyStorePath = keyStorePath;

        if (Files.exists(keyStorePath)) {
            try (InputStream fis = Files.newInputStream(keyStorePath)) {
                keyStore.load(fis, password);
                log.info(lang.argsNonTopKey("loaded-keystore", keyStorePath));
            } finally {
                KeyDestroyHelper.zeroing(password);
            }
        } else {
            // 파일이 없으면 로드하지 않고 초기화 상태 유지 (새로 생성을 위함)
            log.warn(lang.argsNonTopKey("loaded-empty-keystore", keyStorePath));
            try {
                keyStore.load(null, null);
            } catch (IOException e) {
                throw new EntLibSecureJCAJCEStoreProcessException(KeyStoreManager.class, "key-store-loading-exc", e);
            } finally {
                KeyDestroyHelper.zeroing(password);
            }
        }
    }

    /**
     * 트러스트스토어를 파일에서 로드합니다.
     * <p>
     * 트러스트스토어 로드 시, 비밀번호 배열은 영소거되지 않습니다만
     * 안전한 비밀번호 설계는 여전히 권장됩니다.
     *
     * @param trustStorePath 트러스트스토어 파일 경로
     * @param password       트러스트스토어 비밀번호
     */
    public void loadTrustStore(@NotNull Path trustStorePath, char @NotNull [] password)
            throws IOException, CertificateException, NoSuchAlgorithmException {
        Objects.requireNonNull(trustStorePath);
        Objects.requireNonNull(password);

        this.trustStorePath = trustStorePath;

        if (Files.exists(trustStorePath)) {
            try (InputStream fis = Files.newInputStream(trustStorePath)) {
                trustStore.load(fis, password);
                log.info(lang.argsNonTopKey("loaded-truststore", trustStorePath));
            }
        } else {
            log.warn(lang.argsNonTopKey("loaded-empty-truststore", trustStorePath));
            try {
                trustStore.load(null, null);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * 변경 사항을 키스토어 파일에 영구 저장합니다.
     * <p>
     * 안정성 강화: 임시 파일에 기록 후 원자적 이동을 수행하여 파일 손상을 방지합니다.
     * 사용된 비밀번호 배열은 즉시 영소거됩니다.
     *
     * @param password 저장에 사용할 비밀번호
     */
    public void storeKeyStore(char @NotNull [] password)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, EntLibSecureJCAJCEStoreProcessException {
        if (this.keyStorePath == null) {
            throw new EntLibSecureJCAJCEStoreProcessException(KeyStoreManager.class, "keystore-path-exc");
        }
        saveStoreSafe(this.keyStore, this.keyStorePath, password);
    }

    /**
     * 변경 사항을 트러스트스토어 파일에 영구 저장합니다.
     *
     * @param password 저장에 사용할 비밀번호
     */
    public void storeTrustStore(char @NotNull [] password)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, EntLibSecureJCAJCEStoreProcessException {
        if (this.trustStorePath == null) {
            throw new EntLibSecureJCAJCEStoreProcessException(KeyStoreManager.class, "truststore-path-exc");
        }
        saveStoreSafe(this.trustStore, this.trustStorePath, password);
    }

    /**
     * 인증서가 트러스트스토어에서 신뢰할 수 있는지 확인합니다.
     *
     * @param certificate 확인할 인증서
     * @return 신뢰할 수 있으면 true, 그렇지 않으면 false
     */
    public boolean isTrusted(@NotNull X509Certificate certificate) {
        Objects.requireNonNull(certificate);

        try {
            // 직접 별칭으로 찾기
            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate trustedCert = trustStore.getCertificate(alias);
                if (trustedCert != null && trustedCert.equals(certificate)) {
                    return true;
                }
            }

            // 인증서 체인 검증
            return trustStore.getCertificateAlias(certificate) != null;
        } catch (KeyStoreException e) {
            log.warn(lang.thr("check-cert-in-exc", e));
            return false;
        }
    }

    /**
     * 안전한 저장을 위한 내부 헬퍼 메소드입니다.
     * <p>
     * 저장 후 비밀번호 영소거를 위해 사용됩니다.
     */
    private void saveStoreSafe(KeyStore store, Path path, char[] password)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {

        // 1. 임시 파일 생성 (.tmp)
        Path tempPath = path.resolveSibling(path.getFileName() + ".tmp");

        try (FileOutputStream fos = new FileOutputStream(tempPath.toFile())) {
            store.store(fos, password);
            fos.getFD().sync(); // 디스크 동기화 강제
        } finally {
            // 주의! 호출자가 전달한 원본 배열을 수정하기 때문에 호출자가 이 동작을 인지해야 함
            KeyDestroyHelper.zeroing(password);
        }

        // 2. 원자적 이동
        // 파일 쓰기 완료 후 교체하기 때문에 쓰기 도중 실패해도 원본 파일은 안전
        Files.move(tempPath, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        log.info(lang.argsNonTopKey("saved-keystore", path));
    }

    // --- Entry Management Methods ---

    public void setKeyEntry(@NotNull String alias, @NotNull PrivateKey privateKey,
                            char @NotNull [] password, @Nullable Certificate[] chain)
            throws KeyStoreException {
        Objects.requireNonNull(alias);
        Objects.requireNonNull(privateKey);
        Objects.requireNonNull(password);

        try {
            keyStore.setKeyEntry(alias, privateKey, password, chain);
            log.info(lang.argsNonTopKey("save-key-entry", alias));
        } finally {
            // 비밀번호는 KeyStore 내부 로직에서 사용된 후 여기서 소거
            KeyDestroyHelper.zeroing(password);
        }
    }

    public void setKeystoreCertificateEntry(@NotNull String alias, @NotNull Certificate certificate)
            throws KeyStoreException {
        Objects.requireNonNull(alias);
        Objects.requireNonNull(certificate);
        keyStore.setCertificateEntry(alias, certificate);
        log.info(lang.argsNonTopKey("set-keystore-cert-entry", alias));
    }

    public void setTruststoreCertificateEntry(@NotNull String alias, @NotNull Certificate certificate)
            throws KeyStoreException {
        Objects.requireNonNull(alias);
        Objects.requireNonNull(certificate);
        trustStore.setCertificateEntry(alias, certificate);
        log.info(lang.argsNonTopKey("set-truststore-cert-entry", alias));
    }

    public void deleteKeystoreEntry(@NotNull String alias) throws KeyStoreException {
        Objects.requireNonNull(alias);
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
            log.info(lang.args("delete-keystore-entry", alias));
        } else {
            log.warn(lang.args("delete-not-exists-alise-in-keystore-entry", alias));
        }
    }

    public void deleteTrustedEntry(@NotNull String alias) throws KeyStoreException {
        Objects.requireNonNull(alias);
        if (trustStore.containsAlias(alias)) {
            trustStore.deleteEntry(alias);
            log.info(lang.args("delete-truststore-entry", alias));
        } else {
            log.warn(lang.args("delete-not-exists-alise-in-truststore-entry", alias));
        }
    }
}