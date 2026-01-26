/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.io;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.util.wrapper.Pair;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

@Slf4j
public final class PemUtil {

    private static final Path KEY_STORAGE_DIR = Paths.get("internal")  // 저장 전용 폴더
            .toAbsolutePath()
            .normalize();

    public static void savePublicKeyToPEM(final @NotNull PublicKey publicKey, final @NotNull String filename) {
        Objects.requireNonNull(publicKey);
        Objects.requireNonNull(filename);
        final Pair<Path, Path> pathPair = checkTraversal(filename);

        byte[] encoded = publicKey.getEncoded();
        Path tempPath = null;
        try {
            tempPath = Files.createTempFile(pathPair.getSecond(), "temp-", ".pem");
            try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(Files.newOutputStream(tempPath)))) {
                pemWriter.writeObject(new PemObject("PUBLIC KEY", encoded));
            }

            // POSIX and move
            checkPosixFilePerm(publicKey, tempPath);
            Files.move(tempPath, pathPair.getFirst(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            if (tempPath != null && Files.exists(tempPath)) {
                try {
                    Files.delete(tempPath);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
            throw new RuntimeException(e);
        } finally {
            if (encoded != null)
                Arrays.fill(encoded, (byte) 0);
        }
    }

    public static void savePrivateKeyToPEM(final @NotNull PrivateKey privateKey, final @NotNull String filename, final char @NotNull [] password) {
        Objects.requireNonNull(privateKey);
        Objects.requireNonNull(filename);
        Objects.requireNonNull(password);
        if (password.length < 8)
            throw new IllegalArgumentException("패스워드가 너무 약합니다. 최소 8자 이상 사용하세요.");
        final Pair<Path, Path> pathPair = checkTraversal(filename);

        byte[] encoded = privateKey.getEncoded();
        Path tempPath = null;
        try {

            // PKCS#8 형식으로 개인키를 암호화하기 위한 설정
            OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(PKCS8Generator.AES_256_CBC)
                    .setProvider(InternalFactory.getBCNormalProvider())
                    .setRandom(InternalFactory.getSafeRandom())
                    .setIterationCount(100_000)
                    .build(password);

            JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(privateKey, encryptor);

            tempPath = Files.createTempFile(pathPair.getSecond(), "temp-", ".pem");
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(Files.newOutputStream(tempPath)))) {
                pemWriter.writeObject(pkcs8Generator);
                pemWriter.flush();
            }

            // POSIX and move
            checkPosixFilePerm(privateKey, tempPath);
            Files.move(tempPath, pathPair.getFirst(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            if (tempPath != null && Files.exists(tempPath)) {
                try {
                    Files.delete(tempPath);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } finally {
            if (encoded != null)
                Arrays.fill(encoded, (byte) 0);
            Arrays.fill(password, '\0');
        }
    }

    public static PublicKey loadPublicKeyFromPEM(final @NotNull String filename) {
        Objects.requireNonNull(filename);
        final Pair<Path, Path> pathPair = checkTraversal(filename);

        try (FileReader fileReader = new FileReader(pathPair.getFirst().toFile());
             PEMParser pemParser = new PEMParser(fileReader)) {
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(InternalFactory.getBCNormalProvider());
            return converter.getPublicKey(publicKeyInfo);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey loadPKCS8PrivateKetFromPEM(final @NotNull String filename, final char @NotNull [] password) {
        Objects.requireNonNull(filename);
        Objects.requireNonNull(password);
        final Pair<Path, Path> pathPair = checkTraversal(filename);

        try (FileReader fileReader = new FileReader(pathPair.getFirst().toFile());
             PEMParser pemParser = new PEMParser(fileReader)) {
            PKCS8EncryptedPrivateKeyInfo pkcs8PrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();
            // 암호화된 경우 PKCS#8 형식
            if (password.length == 0)
                throw new IllegalArgumentException("비밀키 로드 시 패스워드가 필요합니다!");

            // 암호화된 키를 복호화하기 위한 제공자 빌더(AES256 복호화에 필요한 정보 포함)
            InputDecryptorProvider decryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                    .setProvider(InternalFactory.getBCNormalProvider())
                    .build(password);

            // 개인 키 정보 복호화
            PrivateKeyInfo privateKeyInfo = pkcs8PrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);

            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(InternalFactory.getBCNormalProvider());
            return converter.getPrivateKey(privateKeyInfo);
        } catch (IOException | OperatorCreationException | PKCSException e) {
            throw new RuntimeException(e);
        }
    }

    ///  전자: Full, 후자: Parent
    private static Pair<Path, Path> checkTraversal(final @NotNull String filename) {
        if (filename.isEmpty() || filename.contains("..") || filename.contains("\\") || filename.startsWith("/") || filename.startsWith(File.separator))
            throw new IllegalArgumentException("잘못된 파일명 형식입니다: " + filename);
        Path fullPath = KEY_STORAGE_DIR.resolve(filename).normalize();
        if (!fullPath.startsWith(KEY_STORAGE_DIR))
            throw new IllegalArgumentException("허용된 저장 디렉토리를 벗어났습니다.");
        Path parent = fullPath.getParent();
        if (parent == null || !Files.exists(parent) || !Files.isWritable(parent))
            throw new IllegalArgumentException("디렉토리가 존재하지 않거나 쓰기 권한이 없습니다: " + parent);
        return new Pair<>(fullPath, parent);
    }

    ///  POSIX 파일 권한 설정
    private static void checkPosixFilePerm(final @NotNull Key key, Path tempPath) throws IOException {
        try {
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString(key instanceof PrivateKey ? "rw-------" : "rw-r--r--");
            Files.setPosixFilePermissions(tempPath, perms);
        } catch (UnsupportedOperationException e) {
            // Windows 등 non-POSIX: 대체 처리 (예: 로그만)
            log.warn("POSIX 권한 설정 미지원 플랫폼입니다. 파일 권한을 수동 확인하세요.");
        }
    }

}