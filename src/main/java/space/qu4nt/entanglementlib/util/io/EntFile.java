/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.io;

import com.quant.quantregular.annotations.QuantPerformance;
import com.quant.quantregular.annotations.QuantStd;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import space.qu4nt.entanglementlib.InternalFactory;
import space.qu4nt.entanglementlib.exception.security.EntLibSecurityException;
import space.qu4nt.entanglementlib.exception.utility.EntLibUtilityException;
import space.qu4nt.entanglementlib.resource.language.LanguageInstanceBased;
import space.qu4nt.entanglementlib.security.algorithm.Digest;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.FileSystem;
import java.nio.file.attribute.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.BiConsumer;

/**
 * 해당 클래스의 구현에 다음을 명심해야 합니다.
 * <ul>
 *     <li>경로 조작(path traversal) 방지</li>
 *     <li>화이트리스트 방식의 입력 유효성 검사</li>
 *     <li>최소 권한 원칙 적용</li>
 *     <li>파일 무결성 점검</li>
 * </ul>
 * <p>
 * 이 클래스는 {@code ENTFILE_BASE_DIR} 환경 변수에 할당된 경로를
 * 기준으로 트래버셜 보안을 수행합니다. 파일을 코드 내에서 자유롭게 관리할 수 없음을
 * 참고하세요.
 * <p>
 * 이 규칙을 사용하지 않는 파일 관리 기능을 사용하려면
 * 내부 {@link Unchecked} 클래스를 사용하세요.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
@QuantStd(reqEnv = "ENTFILE_BASE_DIR")
public final class EntFile {

    // 허용된 기본 디렉토리 (설정 파일 또는 환경 변수에서 로드)
    private static final String BASE_DIR = InternalFactory.envEntanglementHomeDir();

    /**
     * 데이터를 안전하게 파일로 저장하고, 저장된 데이터의 무결성 해시를 반환하는 메소드입니다.
     *
     * @param relativePath 저장할 파일의 상대 경로
     * @param data         저장할 바이트 데이터
     * @param overwrite    기존 파일 존재 시 덮어쓰기 여부
     * @return 저장된 데이터의 SHA3-256 해시 Hex 문자열
     * @throws IOException             쓰기 과정에서 문제가 발생한 경우
     * @throws EntLibSecurityException 보안 위반 또는 파일 중복 시
     */
    @QuantPerformance
    public static String saveFileSafely(String relativePath, byte[] data, boolean overwrite)
            throws IOException, EntLibSecurityException {
        // 입력 검증 강화
        if (relativePath == null || data == null) {
            throw new EntLibSecurityException(EntFile.class, "relative-path-of-data-null-exc");
        }
        if (data.length > 1024 * 1024 * 1024) { // 1GB 제한으로 메모리 안정성 확보
            throw new EntLibSecurityException(EntFile.class, "data-size-exc");
        }
        if (!relativePath.matches("^[\\w.-]+(/[\\w.-]+)*$")) {
            throw new EntLibSecurityException(EntFile.class, "whitelist-exc");
        }

        // Path Traversal 방어 강화
        Path basePath = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        if (!basePath.toFile().isDirectory()) {
            throw new EntLibSecurityException(EntFile.class, "base-dir-not-valid-exc");
        }

        Path resolvedPath = basePath.resolve(relativePath).normalize();
        // toRealPath() 대신 부모 디렉토리 real path 확인 (파일 생성 없이 symbolic link 방어)
        Path parentDir = resolvedPath.getParent();
        if (parentDir != null) {
            try {
                parentDir = parentDir.toRealPath(); // 부모 디렉토리 존재 확인 및 real path
            } catch (IOException e) {
                throw new EntLibSecurityException(EntFile.class, "failed-parent-dir-exc", e);
            }
            if (!parentDir.startsWith(basePath)) {
                throw new EntLibSecurityException(EntFile.class, "traversal-attempt-exc");
            }
        }
        if (!resolvedPath.startsWith(basePath)) {
            throw new EntLibSecurityException(EntFile.class, "in-save-traversal-attempt-exc");
        }

        File file = resolvedPath.toFile();

        // 덮어쓰기 정책 확인 (TOCTOU 최소화 위해 옵션에 의존)
        if (file.exists() && !overwrite) {
            throw new EntLibSecurityException(EntFile.class, "file-already-exists-exc");
        }

        // 부모 디렉토리 생성 (필요 시) 및 권한 설정
        if (parentDir != null && !Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
            if (basePath.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Set<PosixFilePermission> dirPerms = PosixFilePermissions.fromString("rwx------");
                Files.setPosixFilePermissions(parentDir, dirPerms);
            }
        }

        // 파일 쓰기 옵션 설정 (원자성 및 안전성 고려)
        Set<StandardOpenOption> options = new HashSet<>();
        options.add(StandardOpenOption.WRITE);
        options.add(StandardOpenOption.CREATE);
        if (overwrite) {
            options.add(StandardOpenOption.TRUNCATE_EXISTING);
        } else {
            options.add(StandardOpenOption.CREATE_NEW);
        }

        // 파일 저장 수행 (메모리 효율성 위해 ByteArrayInputStream 사용)
        Path finalFile;
        try (InputStream inputStream = new ByteArrayInputStream(data)) {
            finalFile = Files.write(resolvedPath, inputStream.readAllBytes(), options.toArray(new StandardOpenOption[0]));
        } catch (IOException e) {
            throw new EntLibSecurityException(EntFile.class, "failed-write-disk-exc", e);
        }

        // 최소 권한 적용 (POSIX 및 Windows ACL 지원)
        try {
            FileSystem fs = basePath.getFileSystem();
            if (fs.supportedFileAttributeViews().contains("posix")) {
                Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(resolvedPath, perms);
            } else if (fs.supportedFileAttributeViews().contains("acl")) {
                AclFileAttributeView aclView = Files.getFileAttributeView(resolvedPath, AclFileAttributeView.class);
                UserPrincipal owner = Files.getOwner(resolvedPath);
                List<AclEntry> acl = new ArrayList<>();
                acl.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(owner)
                        .setPermissions(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA)
                        .build());
                aclView.setAcl(acl);
            }
        } catch (Exception e) {
            log.error(LanguageInstanceBased.create(EntFile.class).args("failed-set-perm", e.getMessage()));
        }

        // 무결성 증명을 위한 해시 계산 및 반환
        try {
            return Hash.hashFile(finalFile, Digest.SHA3_256);
        } catch (NoSuchAlgorithmException e) {
            throw new EntLibSecurityException(EntFile.class, "no-such-alg-exc", e);
        }
    }

    /**
     * 대용량 처리를 위해 파일의 전체 내용을 메모리에 올리지 않고,
     * 경로 보안 검증(트래버셜)이 완료된 {@link InputStream}을 반환하는 메소드입니다.
     *
     * @param relativePath 로드할 파일의 상대 경로 (BASE_DIR 내에서만 허용)
     * @return 버퍼링된 입력 스트림
     * @throws IOException             읽기 과정에서 문제가 발생한 경우
     * @throws EntLibSecurityException 보안 위반 시 (경로 조작 등)
     * @see #openStreamSafelyExpectedHash(String, String) 무결성 검증이 필요한 경우
     */
    public static InputStream openStreamSafely(String relativePath) throws IOException, EntLibSecurityException {
        // 입력 검증: null 체크 및 허용 문자만
        if (relativePath == null) {
            throw new EntLibSecurityException(EntFile.class, "relative-path-null-exc");
        }
        // 화이트리스트 & Path Traversal 방어
        final Path resolvedPath = checkWhitelistAndPathTraversal(relativePath);

        // 새로운 스트림을 열어 반환
        return new BufferedInputStream(Files.newInputStream(resolvedPath));
    }

    /**
     * 대용량 처리를 위해 파일의 전체 내용을 메모리에 올리지 않고,
     * 복합 보안 검증(트래버셜, 무결성)이 완료된 {@link InputStream}을 반환하는 메소드입니다.
     *
     * @param relativePath 로드할 파일의 상대 경로 (BASE_DIR 내에서만 허용)
     * @param expectedHash 예상되는 파일의 {@code SHA3-256} 해시 값 (소문자 16진수 문자열)
     * @return 버퍼링된 입력 스트림
     * @throws IOException             읽기 과정에서 문제가 발생한 경우
     * @throws EntLibSecurityException 보안 위반 시 (경로 조작, 무결성 실패 등)
     * @see #openStreamSafely(String) 무결성 검증이 필요 없는 경우
     */
    public static InputStream openStreamSafelyExpectedHash(String relativePath, @NotNull String expectedHash) throws IOException, EntLibSecurityException {
        // 입력 검증: null 체크 및 허용 문자만
        if (expectedHash == null) {
            throw new EntLibSecurityException(EntFile.class, "relative-path-or-expected-hash-null-exc");
        }
        // 화이트리스트 & Path Traversal 방어
        final Path resolvedPath = checkWhitelistAndPathTraversal(relativePath);

        // 무결성 검사: Digest 클래스를 사용해 안전하고 메모리 효율적으로 해시 계산
        String actualHash;
        try {
            actualHash = Hash.hashFile(resolvedPath, Digest.SHA3_256);
        } catch (NoSuchAlgorithmException e) {
            throw new EntLibSecurityException(EntFile.class, "not-support-jvm-exc", e);
        }

        // 타이밍 공격에 안전한 해시 비교
        if (!Hash.isEqual(actualHash, expectedHash.toLowerCase())) {
            throw new EntLibSecurityException(EntFile.class, "load-hash-equal-exc");
        }

        // 새로운 스트림을 열어 반환
        return new BufferedInputStream(Files.newInputStream(resolvedPath));
    }

    /**
     * 보안 검증을 위한 헬퍼 메소드입니다.
     *
     * @param relativePath 기준점 상대 경로
     * @return {@link Path#resolve(Path)}된 최종 경로
     */
    @NotNull
    private static Path checkWhitelistAndPathTraversal(final @NotNull String relativePath) {
        // 추 후 화이트리스트 열거 방식으로 수정
        if (!relativePath.matches("^[a-zA-Z0-9_/.-]+$")) {
            throw new EntLibSecurityException(EntFile.class, "whitelist-exc");
        }

        // Path Traversal 방어: 정규화 후 BASE_DIR 범위 검사
        Path basePath = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        if (!basePath.toFile().isDirectory()) {
            throw new EntLibSecurityException(EntFile.class, "not-valid-or-accessible-exc");
        }

        Path resolvedPath = basePath.resolve(relativePath).normalize();
        if (!resolvedPath.startsWith(basePath)) {
            throw new EntLibSecurityException(EntFile.class, "load-traversal-attempt-exc");
        }

        File file = resolvedPath.toFile();
        if (!file.isFile() || !file.canRead()) {
            throw new EntLibSecurityException(EntFile.class, "load-file-not-found-or readable-exc");
        }
        return resolvedPath;
    }

    /**
     * 파일 스트리밍을 통해 데이터를 버퍼 단위로 처리하는 메소드입니다.
     * 입력 파일에서 데이터를 읽어와 콜백 함수를 통해 처리한 후 출력 파일에 씁니다.
     *
     * @param inputPath            입력 파일의 경로
     * @param outputPath           출력 파일의 경로
     * @param inputAllocateSize    입력 데이터를 읽을 버퍼 할당 사이즈
     * @param outputAllocateSize   출력 데이터를 쓸 버퍼 할당 사이즈
     * @param ioByteBufferCallback 각 버퍼 처리 단계에서 호출될 콜백 함수. 입력 버퍼와 출력 버퍼를 인자로 받습니다.
     *                             콜백이 {@code null}인 경우, 데이터는 단순히 입력에서 출력으로 복사됩니다.
     * @return 마지막으로 출력 채널에 쓰여진 바이트 수, 아무것도 쓰여지지 않은 경우 {@code 0}
     * @throws IOException 파일 읽기 또는 쓰기 과정에서 문제가 발생한 경우
     */
    public static int byteBufferStreaming(@NotNull Path inputPath,
                                          @NotNull Path outputPath,
                                          int inputAllocateSize,
                                          int outputAllocateSize,
                                          @Nullable BiConsumer<@NotNull ByteBuffer, @NotNull ByteBuffer> ioByteBufferCallback)
            throws IOException {
        Objects.requireNonNull(inputPath);
        Objects.requireNonNull(outputPath);

        if (inputAllocateSize < 1 || outputAllocateSize < 1)
            throw new EntLibUtilityException(EntFile.class, "invalid-buffer-size-exc", inputAllocateSize, outputAllocateSize);

        try (FileChannel inputChannel = FileChannel.open(inputPath, StandardOpenOption.READ);
             FileChannel outputChannel = FileChannel.open(outputPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {

            ByteBuffer inputBuffer = ByteBuffer.allocate(inputAllocateSize);
            ByteBuffer outputBuffer = ByteBuffer.allocate(outputAllocateSize);

            int writtenByte = 0;
            while (inputChannel.read(inputBuffer) != -1) {
                inputBuffer.flip();
                outputBuffer.clear();

                if (ioByteBufferCallback != null) {
                    ioByteBufferCallback.accept(inputBuffer, outputBuffer);
                } else {
                    // 콜백이 없으면 입력 버퍼의 내용을 출력 버퍼로 직접 복사
                    outputBuffer.put(inputBuffer);
                }

                outputBuffer.flip();
                writtenByte = outputChannel.write(outputBuffer);
                inputBuffer.compact();
            }
            return writtenByte;
        }
    }

    /**
     * 경로 트래버셜, 무결성 검사를 수행하지 않고 파일 및 디렉토리를 관리하는 클래스입니다.
     * <p>
     * 호출 성능에만 초점을 맞추어 개발되었기 때문에 보안이 필요한 로직에는 사용하지 않을 것을
     * 권장합니다.
     *
     * @author Q. T. Felix
     * @since 1.0.0
     */
    @ApiStatus.Experimental
    public static final class Unchecked {

        /**
         * 스트림에서 데이터를 읽어와 파일로 저장합니다.
         * 이 메소드는 대용량 파일을 효율적으로 처리하기 위해 스트림을 사용하며,
         * 결과물에 대해 별도의 권한 작업을 수행하지 않습니다.
         * <p>
         * 전달받은 경로의 부모 디렉토리가 존재하지 않는 경우 생성합니다.
         * 생성에는 {@link Files#createDirectories(Path, FileAttribute[])}
         * 메소드가 사용됩니다.
         *
         * @param path        저장할 파일의 경로
         * @param inputStream 저장할 데이터의 입력 스트림
         * @param overwrite   기존 파일 존재 시 덮어쓰기 여부
         * @return 결과 경로
         * @throws IOException 쓰기 과정에서 문제가 발생한 경우
         */
        @NotNull
        public static Path saveFile(final @NotNull Path path, final @NotNull InputStream inputStream, boolean overwrite) throws IOException {
            Path parentDir = path.getParent();
            if (parentDir != null && !Files.exists(parentDir))
                Files.createDirectories(parentDir);

            if (overwrite) {
                Files.copy(inputStream, path, StandardCopyOption.REPLACE_EXISTING);
            } else {
                // StandardCopyOption이 지정되지 않으면 대상 파일이 이미 있는 경우 FileAlreadyExistsException을 던짐
                // 이는 StandardOpenOption.CREATE_NEW와 유사하게 동작
                Files.copy(inputStream, path);
            }
            return path;
        }

        /**
         * 파일을 열어 입력 스트림을 반환합니다.
         * 대용량 파일을 효율적으로 처리하기 위해 버퍼링된 스트림 객체
         * {@link BufferedInputStream}을 사용합니다.
         *
         * @param path 열 파일의 경로
         * @return 버퍼링된 입력 스트림
         * @throws IOException 읽기 과정에서 문제가 발생한 경우
         */
        public static InputStream openStream(final @NotNull Path path) throws IOException {
            return new BufferedInputStream(Files.newInputStream(path));
        }
    }

}
