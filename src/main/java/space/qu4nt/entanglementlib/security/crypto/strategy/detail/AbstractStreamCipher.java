/*
 * Copyright © 2025-2026 Quant.
 * Under License "PolyForm Noncommercial License 1.0.0".
 */

package space.qu4nt.entanglementlib.security.crypto.strategy.detail;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.jetbrains.annotations.NotNull;
import space.qu4nt.entanglementlib.entlibnative.SensitiveDataContainer;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalArgumentException;
import space.qu4nt.entanglementlib.exception.secure.EntLibSecureIllegalStateException;
import space.qu4nt.entanglementlib.security.KeyDestroyHelper;
import space.qu4nt.entanglementlib.security.crypto.CipherType;
import space.qu4nt.entanglementlib.security.crypto.EntLibAlgorithmType;
import space.qu4nt.entanglementlib.security.crypto.strategy.StreamCipherStrategy;

import java.nio.ByteBuffer;

/// 스트림 암호 알고리즘의 공통 기능을 제공하는 추상 클래스입니다.
///
/// ChaCha20 등의 스트림 암호 구현체가 이 클래스를 상속합니다.
///
/// @author Q. T. Felix
/// @see StreamCipherStrategy
/// @since 1.1.0
public abstract class AbstractStreamCipher implements StreamCipherStrategy {

    /**
     * 암호화 알고리즘 타입입니다.
     */
    private final @NotNull CipherType base;

    /**
     * BouncyCastle 스트림 암호 엔진입니다.
     */
    private final @NotNull StreamCipher streamCipherEngine;

    protected SensitiveDataContainer iv;

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

    @Override
    public void iv(Object raw) throws EntLibSecureIllegalArgumentException {
        switch (raw) {
            case byte[] b -> this.iv = new SensitiveDataContainer(b, true);
            case Integer i -> {
                if (i != 12)
                    throw new EntLibSecureIllegalArgumentException("AEAD 지원 모드의 경우 IV의 길이는 12이어야 합니다!");
                this.iv = new SensitiveDataContainer(i);
            }
            case SensitiveDataContainer s -> this.iv = s;
            case null, default -> throw new EntLibSecureIllegalArgumentException("유효한 IV 할당 타입이 아닙니다!");
        }
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
    protected int processStreamCipher(boolean encrypt, CipherParameters params, byte[] input, int inOff, int length, byte[] output, int outOff) throws EntLibSecureIllegalArgumentException {
        try {
            streamCipherEngine.init(encrypt, params);
        } catch (IllegalArgumentException e) {
            throw new EntLibSecureIllegalArgumentException("StreamCipher 암호화에 실패했습니다! 아마 다음의 이유로 실패했을 겁니다.\n" +
                    "\t\t1. IV(초기화 벡터) 사이즈가 8 미만이거나 초과하는 경우", e);
        }
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
    protected byte processStreamByte(boolean encrypt, CipherParameters params, byte input) throws EntLibSecureIllegalArgumentException {
        try {
            streamCipherEngine.init(encrypt, params);
        } catch (IllegalArgumentException e) {
            throw new EntLibSecureIllegalArgumentException("StreamCipher 복호화에 실패했습니다! 아마 다음의 이유로 실패했을 겁니다.\n" +
                    "\t\t1. IV(초기화 벡터) 사이즈가 8 미만이거나 초과하는 경우", e);
        }
        return streamCipherEngine.returnByte(input);
    }

    protected byte[] plainCaster(Object plain) throws EntLibSecureIllegalStateException {
        if (plain instanceof byte[] b) {
            plain = b.clone();
            KeyDestroyHelper.zeroing(b);
        } else if (plain instanceof SensitiveDataContainer s) {
            s.exportData();
            plain = s.getSegmentData();
        } else if (plain instanceof ByteBuffer bb) {
            final byte[] arr = new byte[bb.remaining()];
            plain = bb.get(arr);
            KeyDestroyHelper.zeroing(arr);
        }
        //noinspection DataFlowIssue
        return (byte[]) plain;
    }
}