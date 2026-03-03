package space.qu4nt.entanglementlib.security.entlibnative;

import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.core.exception.security.checked.ELIBSecurityIOException;
import space.qu4nt.entanglementlib.core.exception.security.critical.ELIBSecurityNativeCritical;
import space.qu4nt.entanglementlib.security.EntanglementLibSecurityConfig;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

// todo 이 클래스 호출 시점에 국제화 파일 로드돼잇을거임
@Slf4j
public final class NativeLoader {

    private static volatile boolean loaded = false;

    private NativeLoader() {
        throw new UnsupportedOperationException("cannot access");
    }

    private static synchronized void loadSuccess() {
        loaded = true;
        EntLibNativeManager.setup();
    }

    public static synchronized void loadNativeLibrary(final @NotNull EntanglementLibSecurityConfig config) {
        if (loaded) return;

        try {
            NativePlatform os = NativePlatform.detectOs();
            if (os == NativePlatform.UNKNOWN)
                throw new ELIBSecurityNativeCritical("지원하지 않는 운영체제입니다!");

            String fileName = os.buildFileName(config.getNativeContext().getNativeFilename());

            // 사용자 할당 시 외부 절대 경로 탐색
            final String dirName = config.getNativeContext().getNativeDirName();
            Path externalPath = Path.of(dirName);
            Path exactExternalFile = externalPath.resolve(fileName);

            log.info(exactExternalFile.toString());

            // 사용자가 파일명까지 포함한 절대 경로를 입력했거나, 디렉터리 경로를 입력한 경우 모두 처리
            if (Files.exists(externalPath) && !Files.isDirectory(externalPath)) {
                System.load(externalPath.toAbsolutePath().toString());
                loadSuccess();
                return;
            } else if (Files.exists(exactExternalFile)) {
                System.load(exactExternalFile.toAbsolutePath().toString());
                loadSuccess();
                return;
            }

            // jar 내부 자원 로드
            String architecture = NativePlatform.detectArchitecture();
            String resourcePath = dirName + "/" + os.name().toLowerCase() + "/" + architecture + "/" + fileName;

            extractAndLoadFromJar(resourcePath, fileName);
            loadSuccess();
        } catch (UnsatisfiedLinkError e) {
            throw new ELIBSecurityNativeCritical(
                    "파일명이 절대 경로명이 아니거나, " +
                    "네이티브 라이브러리가 VM과 정적으로 연결되지 않거나, " +
                    "호스트 시스템에서 라이브러리를 네이티브 라이브러리 이미지에 매핑할 수 없습니다!");
        } catch (IllegalCallerException e) {
            throw new ELIBSecurityNativeCritical("현재 모듈은 네이티브 액세스 권한이 없습니다!");
        } catch (ELIBSecurityIOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void extractAndLoadFromJar(String resourcePath, String fileName) throws ELIBSecurityIOException {
        try (InputStream is = NativeLoader.class.getResourceAsStream(resourcePath)) {
            if (is == null)
                throw new ELIBSecurityNativeCritical("jar 내부 '" + resourcePath + "' 경로에서 네이티브 라이브러리를 찾을 수 없습니다!");

            Path tempFile = createSecureTempFile(fileName);
            tempFile.toFile().deleteOnExit();

            Files.copy(is, tempFile, StandardCopyOption.REPLACE_EXISTING);
            System.load(tempFile.toAbsolutePath().toString());

        } catch (IOException e) {
            throw new ELIBSecurityIOException("임시 파일 생성 및 복사(덮어쓰기)에 실패했습니다!", e);
        }
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    private static Path createSecureTempFile(String fileName) throws IOException {
        int dotIndex = fileName.lastIndexOf('.');
        String prefix = fileName.substring(0, dotIndex) + "-";
        String suffix = fileName.substring(dotIndex);

        boolean isPosix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

        if (isPosix) {
            // POSIX 호환 시스템 (linux, macos): 파일 권한 엄격 제한
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
            return Files.createTempFile(prefix, suffix, PosixFilePermissions.asFileAttribute(perms));
        } else {
            // 윈도우 등 non POSIX 시스템: 기본 임시 파일 생성 후 읽기/쓰기/실행 권한 제어
            Path tempFile = Files.createTempFile(prefix, suffix);
            tempFile.toFile().setReadable(true, true);
            tempFile.toFile().setWritable(true, true);
            tempFile.toFile().setExecutable(true, true);
            return tempFile;
        }
    }
}
