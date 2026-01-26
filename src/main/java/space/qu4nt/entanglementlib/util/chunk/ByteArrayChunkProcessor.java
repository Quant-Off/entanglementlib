/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.chunk;

import lombok.extern.slf4j.Slf4j;

import java.util.Objects;
import java.util.stream.IntStream;

/**
 * 바이트 배열을 청크 단위로 처리하기 위한 클래스입니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@Slf4j
public class ByteArrayChunkProcessor {

    /**
     * 대용량 바이트 배열을 청크 단위로 처리하기 위한 메소드입니다.
     * <p>
     * 용량이 적은 일반 데이터도 문제 없이 처리할 수 있습니다.
     *
     * @param data      처리할 바이트 배열
     * @param chunkSize 1 이상 정수의 청크 크기
     * @param processor 각 청크를 처리할 함수형 인터페이스
     * @param parallel  병렬 처리 여부 (멀티스레드에서 사용하는 경우 true, 그렇지 않으면 false)
     * @throws IllegalArgumentException 입력이 유효하지 않은 경우
     * @throws RuntimeException         처리 중 예외 발생 시
     */
    public static void processInChunks(byte[] data, int chunkSize, ChunkProcessor<byte[]> processor, boolean parallel) {
        Objects.requireNonNull(processor);
        if (data == null || data.length == 0)
            throw new IllegalArgumentException("The input byte array is null or empty");
        if (chunkSize <= 0)
            throw new IllegalArgumentException("Chunk size must be a positive number");

        long startMill = System.currentTimeMillis();
        log.debug("ByteBuffer 청크 작업 - 데이터 길이: {}, 청크 사이즈: {}, 병렬 처리 여부: {}", data.length, chunkSize, parallel);

        int length = data.length;
        IntStream range = IntStream
                .range(0, (length + chunkSize - 1) / chunkSize)
                .map(i -> i * chunkSize);

        // 병렬 처리
        if (parallel) {
            range = IntStream
                    .range(0, (length + chunkSize - 1) / chunkSize)
                    .map(i -> i * chunkSize)
                    .parallel();
        }

        range.forEach(start -> {
            int end = Math.min(start + chunkSize, length);
            int chunkLength = end - start;
            try {
                processor.process(data, start, chunkLength);
            } catch (Exception e) {
                log.error("ByteBuffer 청크 작업 중 오프셋 {}에서 예외가 발생했습니다!", start, e);
            }
        });
        log.debug("ByteBuffer 청크 작업 완료: {}ms 소요", System.currentTimeMillis() - startMill);
    }

    /**
     * 대용량 바이트 배열을 청크 단위로 처리하기 위한 메소드입니다.
     * <p>
     * 용량이 적은 일반 데이터도 문제 없이 처리할 수 있으며, 해당 메소드는
     * 작업을 병렬이 아닌 순차적으로 처리합니다.
     *
     * @param data      처리할 바이트 배열
     * @param chunkSize 1 이상 정수의 청크 크기
     * @param processor 각 청크를 처리할 함수형 인터페이스
     * @throws IllegalArgumentException 입력이 유효하지 않은 경우
     * @throws RuntimeException         처리 중 예외 발생 시
     */
    public static void processInChunks(byte[] data, int chunkSize, ChunkProcessor<byte[]> processor) {
        processInChunks(data, chunkSize, processor, false);
    }
}
