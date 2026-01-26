/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.io;

import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.security.crypto.Digest;
import space.qu4nt.entanglementlib.util.chunk.ByteArrayChunkProcessor;
import space.qu4nt.entanglementlib.util.wrapper.Hex;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

public final class Hash {

    /**
     * 기본 버퍼 크기: 1MB (대용량 파일에서도 안전합니다.)
     */
    private static final int BUFFER_SIZE = 1024 * 1024; // 1MB

    public static String hash(byte @NotNull [] data, Digest digest, int chunkSize) throws NoSuchAlgorithmException {
        Objects.requireNonNull(data);
        Objects.requireNonNull(digest);

        MessageDigest md = MessageDigest.getInstance(digest.getName());
        if (data.length > 1023 && chunkSize > 0) {
            ByteArrayChunkProcessor.processInChunks(data, chunkSize, md::update);
        } else {
            md.update(data, 0, data.length);
        }
        return Hex.toHexString(md.digest());
    }

    /**
     * 문자 배열의 해시값을 산출하는 메소드입니다.
     * 문자열은 {@code UTF-8}로 인코딩되어 처리됩니다.
     *
     * @param data   해시를 산출할 문자 배열
     * @param digest 사용할 해시 알고리즘
     * @return 소문자 16진수 해시 문자열
     * @throws NoSuchAlgorithmException 지원하지 않는 알고리즘 요청 시
     */
    public static String hash(final char @NotNull [] data, Digest digest) throws NoSuchAlgorithmException {
        Objects.requireNonNull(data);
        Objects.requireNonNull(digest);

        byte[] bytes = new String(data).getBytes(StandardCharsets.UTF_8);
        return hash(bytes, digest, 0);
    }

    /**
     * 파일의 해시값을 16진수 문자열로 반환하는 메소드입니다.
     *
     * @param filePath 파일 경로
     * @param digest   사용할 해시 알고리즘
     * @return 소문자 16진수 해시 문자열
     * @throws IOException              파일 읽기 실패 시
     * @throws NoSuchAlgorithmException 지원하지 않는 알고리즘 요청 시
     */
    public static String hashFile(Path filePath, Digest digest)
            throws IOException, NoSuchAlgorithmException {
        Objects.requireNonNull(filePath);
        Objects.requireNonNull(digest);

        MessageDigest md = MessageDigest.getInstance(digest.getName());

        try (FileChannel channel = FileChannel.open(filePath);
             InputStream in = new BufferedInputStream(Channels.newInputStream(channel))) {

            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;

            while ((bytesRead = in.read(buffer)) != -1) {
                md.update(buffer, 0, bytesRead);
            }
        }

        return Hex.toHexString(md.digest());
    }

    /**
     * {@link MappedByteBuffer}를 사용하여{@link #hashFile(Path, Digest)}
     * 메소드보다 대용량 파일에 더 최적화된 버전의 메소드입니다.
     * <p>
     * 메모리 매핑으로 OS가 알아서 페이징 처리하기 때문에 대용량 파일도 안정적입니다.
     *
     * @param filePath 파일 경로
     * @param digest   사용할 해시 알고리즘
     * @return 소문자 16진수 해시 문자열
     */
    public static String hashFileWithMapping(Path filePath, Digest digest)
            throws IOException, NoSuchAlgorithmException {
        Objects.requireNonNull(filePath);
        Objects.requireNonNull(digest);

        MessageDigest md = MessageDigest.getInstance(digest.getName());

        try (RandomAccessFile raf = new RandomAccessFile(filePath.toFile(), "r");
             FileChannel channel = raf.getChannel()) {

            long position = 0;
            long length = channel.size();

            while (position < length) {
                long remaining = length - position;
                long chunk = Math.min(BUFFER_SIZE * 16L, remaining); // 최대 16MB씩 매핑

                MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, position, chunk);
                buffer.load(); // 필요 시 메모리에 로드 (선택적)

                byte[] data = new byte[BUFFER_SIZE];
                int bytesToRead;

                while (buffer.hasRemaining()) {
                    bytesToRead = Math.min(buffer.remaining(), data.length);
                    buffer.get(data, 0, bytesToRead);
                    md.update(data, 0, bytesToRead);
                }

                position += chunk;
            }
        }

        return Hex.toHexString(md.digest());
    }

    /**
     * 두 해시값을 타이밍 공격에 안전하게 비교하는 메소드입니다.
     *
     * @return 일치하면 true, 그렇지 않으면 false
     */
    public static boolean isEqual(String hexHash1, String hexHash2) {
        if (hexHash1 == null || hexHash2 == null) return false;
        if (hexHash1.length() != hexHash2.length()) return false;

        byte[] b1 = HexFormat.of().parseHex(hexHash1);
        byte[] b2 = HexFormat.of().parseHex(hexHash2);
        return MessageDigest.isEqual(b1, b2);
    }

    /**
     * {@link Digest#SHA_256} 다이제스트를 기본으로 사용하여 파일의 해시값을 확인하는 메소드입니다.
     *
     * @return 해시값
     */
    public static String sha256(Path filePath) throws IOException, NoSuchAlgorithmException {
        return hashFile(filePath, Digest.SHA_256);
    }
}
