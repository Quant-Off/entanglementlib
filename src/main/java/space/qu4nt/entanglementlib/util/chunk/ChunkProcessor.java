/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.util.chunk;

/**
 * 대용량 데이터를 청크 단위로 처리할 때 사용되는 함수형 인터페이스입니다.
 * 원본 배열의 오프셋과 길이를 받아 처리합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
@FunctionalInterface
public interface ChunkProcessor<T> {

    /**
     * 해당 메소드를 통해 청크를 처리 로직을 구현할 수 있습니다.
     *
     * @param data   원본 바이트 배열
     * @param offset 청크 시작 오프셋
     * @param length 청크 길이
     * @throws Exception 처리 중 발생할 수 있는 예외
     */
    void process(T data, int offset, int length) throws Exception;

}
