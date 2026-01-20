/*
 * Copyright © 2025 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.experimental.crypto.strategy.detail;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.experimental.crypto.CipherType;
import space.qu4nt.entanglementlib.experimental.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.experimental.crypto.strategy.StreamCipherStrategy;

/**
 * 스트림 암호 알고리즘의 공통 기능을 제공하는 추상 클래스입니다.
 * <p>
 * ChaCha20 등의 스트림 암호 구현체가 이 클래스를 상속합니다.
 * </p>
 *
 * @author Q. T. Felix
 * @since 1.1.0
 * @see StreamCipherStrategy
 */
public abstract class AbstractStreamCipher implements StreamCipherStrategy {

    /**
     * 암호화 알고리즘 타입입니다.
     */
    private final @NotNull CipherType base;

    /**
     * BouncyCastle 스트림 암호 엔진입니다.
     */
    private final @NotNull StreamCipher streamCipherEngine;

    /**
     * 스트림 암호 추상 클래스의 생성자입니다.
     *
     * @param base               암호화 알고리즘 타입
     * @param streamCipherEngine BouncyCastle 스트림 암호 엔진
     */
    protected AbstractStreamCipher(final @NotNull CipherType base, @NotNull StreamCipher streamCipherEngine) {
        this.base = base;
        this.streamCipherEngine = streamCipherEngine;
    }

    /**
     * 이 스트레티지의 알고리즘 타입을 반환하는 메소드입니다.
     *
     * @return 알고리즘 타입
     */
    @Override
    public EntLibAlgorithmType getAlgorithmType() {
        return base;
    }

    /**
     * 스트림 암호 처리를 수행하는 메소드입니다.
     *
     * @param encrypt 암호화이면 {@code true}, 복호화이면 {@code false}
     * @param params  암호화 파라미터
     * @param input   입력 바이트 배열
     * @param inOff   입력 시작 오프셋
     * @param length  처리할 길이
     * @param output  출력 바이트 배열
     * @param outOff  출력 시작 오프셋
     * @return 처리된 바이트 수
     */
    protected int processStreamCipher(boolean encrypt, CipherParameters params, byte[] input, int inOff, int length, byte[] output, int outOff) {
        streamCipherEngine.init(encrypt, params);
        return streamCipherEngine.processBytes(input, inOff, length, output, outOff);
    }

    /**
     * 단일 바이트에 대해 스트림 암호 처리를 수행하는 메소드입니다.
     *
     * @param encrypt 암호화이면 {@code true}, 복호화이면 {@code false}
     * @param params  암호화 파라미터
     * @param input   입력 바이트
     * @return 처리된 바이트
     */
    protected byte processStreamByte(boolean encrypt, CipherParameters params, byte input) {
        streamCipherEngine.init(encrypt, params);
        return streamCipherEngine.returnByte(input);
    }
}