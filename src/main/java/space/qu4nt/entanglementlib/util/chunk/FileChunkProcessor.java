/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.chunk;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.stream.LongStream;

/**
 * 파일을 청크 단위로 처리하기 위한 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.1.0
 */
@Slf4j
public class FileChunkProcessor {

    /**
     * 대용량 파일을 청크 단위로 처리하기 위한 메소드입니다.
     * <p>
     * 용량이 적은 일반 데이터도 문제 없이 처리할 수 있습니다.
     * 프로세서에는 파일 경로, 시작 오프셋, 청크 길이가 전달되며,
     * 프로세서 내부에서 해당 오프셋부터 파일을 읽어 처리해야 합니다.
     *
     * @param data      처리할 파일 경로
     * @param chunkSize 1 이상 정수의 청크 크기 (바이트 단위)
     * @param processor 각 청크를 처리할 함수형 인터페이스
     * @param parallel  병렬 처리 여부 (멀티스레드에서 사용하는 경우 true, 그렇지 않으면 false)
     * @throws IllegalArgumentException 입력이 유효하지 않은 경우
     * @throws RuntimeException         처리 중 예외 발생 시
     */
    public static void processInChunks(Path data, int chunkSize, ChunkProcessor<Path> processor, boolean parallel) {
        Objects.requireNonNull(processor, "processor must not be null");
        if (data == null || Files.notExists(data))
            throw new IllegalArgumentException("The input path is null or not exists");
        if (!Files.isRegularFile(data))
            throw new IllegalArgumentException("The input path is not a regular file");
        if (chunkSize <= 0)
            throw new IllegalArgumentException("Chunk size must be a positive number");

        long startMill = System.currentTimeMillis();
        long fileSize;
        try {
            fileSize = Files.size(data);
        } catch (IOException e) {
            throw new RuntimeException("Failed to get file size", e);
        }

        log.debug("File 청크 작업 - 파일 크기: {} bytes, 청크 사이즈: {}, 병렬 처리 여부: {}", fileSize, chunkSize, parallel);

        if (fileSize == 0) {
            log.debug("File 청크 작업 완료 (빈 파일): {}ms 소요", System.currentTimeMillis() - startMill);
            return;
        }

        long chunkCount = (fileSize + chunkSize - 1) / chunkSize;
        LongStream range = LongStream.range(0, chunkCount);

        if (parallel) {
            range = range.parallel();
        }

        range.forEach(chunkIndex -> {
            long start = chunkIndex * chunkSize;
            int chunkLength = (int) Math.min(chunkSize, fileSize - start);
            try {
                processor.process(data, (int) start, chunkLength);
            } catch (Exception e) {
                log.error("File 청크 작업 중 오프셋 {}에서 예외가 발생했습니다!", start, e);
            }
        });
        log.debug("File 청크 작업 완료: {}ms 소요", System.currentTimeMillis() - startMill);
    }

    /**
     * 대용량 파일을 청크 단위로 처리하기 위한 메소드입니다.
     * <p>
     * 파일 크기가 {@link Integer#MAX_VALUE}보다 큰 경우 이 메소드를 사용하세요.
     * 프로세서에는 파일 경로, 시작 오프셋, 청크 길이가 전달됩니다.
     *
     * @param data      처리할 파일 경로
     * @param chunkSize 1 이상 정수의 청크 크기 (바이트 단위)
     * @param processor 각 청크를 처리할 함수형 인터페이스 (long 오프셋 지원)
     * @param parallel  병렬 처리 여부 (멀티스레드에서 사용하는 경우 true, 그렇지 않으면 false)
     * @throws IllegalArgumentException 입력이 유효하지 않은 경우
     * @throws RuntimeException         처리 중 예외 발생 시
     */
    public static void processInChunksLarge(Path data, int chunkSize, LargeFileChunkProcessor processor, boolean parallel) {
        Objects.requireNonNull(processor, "processor must not be null");
        if (data == null || Files.notExists(data))
            throw new IllegalArgumentException("The input path is null or not exists");
        if (!Files.isRegularFile(data))
            throw new IllegalArgumentException("The input path is not a regular file");
        if (chunkSize <= 0)
            throw new IllegalArgumentException("Chunk size must be a positive number");

        long startMill = System.currentTimeMillis();
        long fileSize;
        try {
            fileSize = Files.size(data);
        } catch (IOException e) {
            throw new RuntimeException("Failed to get file size", e);
        }

        log.debug("Large File 청크 작업 - 파일 크기: {} bytes, 청크 사이즈: {}, 병렬 처리 여부: {}", fileSize, chunkSize, parallel);

        if (fileSize == 0) {
            log.debug("Large File 청크 작업 완료 (빈 파일): {}ms 소요", System.currentTimeMillis() - startMill);
            return;
        }

        long chunkCount = (fileSize + chunkSize - 1) / chunkSize;
        LongStream range = LongStream.range(0, chunkCount);

        if (parallel) {
            range = range.parallel();
        }

        range.forEach(chunkIndex -> {
            long start = chunkIndex * chunkSize;
            int chunkLength = (int) Math.min(chunkSize, fileSize - start);
            try {
                processor.process(data, start, chunkLength);
            } catch (Exception e) {
                log.error("Large File 청크 작업 중 오프셋 {}에서 예외가 발생했습니다!", start, e);
            }
        });
        log.debug("Large File 청크 작업 완료: {}ms 소요", System.currentTimeMillis() - startMill);
    }

    /**
     * 대용량 파일을 청크 단위로 처리하기 위한 메소드입니다.
     * <p>
     * 용량이 적은 일반 데이터도 문제 없이 처리할 수 있으며, 해당 메소드는
     * 작업을 병렬이 아닌 순차적으로 처리합니다.
     *
     * @param data      처리할 파일 경로
     * @param chunkSize 1 이상 정수의 청크 크기 (바이트 단위)
     * @param processor 각 청크를 처리할 함수형 인터페이스
     * @throws IllegalArgumentException 입력이 유효하지 않은 경우
     * @throws RuntimeException         처리 중 예외 발생 시
     */
    public static void processInChunks(Path data, int chunkSize, ChunkProcessor<Path> processor) {
        processInChunks(data, chunkSize, processor, false);
    }

    /**
     * 대용량 파일을 청크 단위로 처리하기 위한 메소드입니다.
     * <p>
     * 파일 크기가 {@link Integer#MAX_VALUE}보다 큰 경우 이 메소드를 사용하세요.
     * 작업을 병렬이 아닌 순차적으로 처리합니다.
     *
     * @param data      처리할 파일 경로
     * @param chunkSize 1 이상 정수의 청크 크기 (바이트 단위)
     * @param processor 각 청크를 처리할 함수형 인터페이스 (long 오프셋 지원)
     * @throws IllegalArgumentException 입력이 유효하지 않은 경우
     * @throws RuntimeException         처리 중 예외 발생 시
     */
    public static void processInChunksLarge(Path data, int chunkSize, LargeFileChunkProcessor processor) {
        processInChunksLarge(data, chunkSize, processor, false);
    }

    /**
     * 2GB 이상의 대용량 파일 청크 처리를 위한 함수형 인터페이스입니다.
     * offset이 long 타입으로 {@link Integer#MAX_VALUE}를 초과하는 오프셋을 지원합니다.
     */
    @FunctionalInterface
    public interface LargeFileChunkProcessor {
        /**
         * 파일 청크를 처리합니다.
         *
         * @param path   파일 경로
         * @param offset 청크 시작 오프셋 (바이트 단위)
         * @param length 청크 길이 (바이트 단위)
         * @throws Exception 처리 중 발생할 수 있는 예외
         */
        void process(Path path, long offset, int length) throws Exception;
    }
}
