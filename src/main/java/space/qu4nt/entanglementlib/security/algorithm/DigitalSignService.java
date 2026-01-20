/*
 * Copyright (c) 2025-2026 Quant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package space.qu4nt.entanglementlib.security.algorithm;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.*;

/**
 * 디지털 서명 서비스를 정의하는 인터페이스입니다.
 * <p>
 * 이 인터페이스는 데이터에 대한 디지털 서명 생성 및 검증과 같은
 * 디지털 서명 작업에 필요한 공통 기능을 제공합니다.
 *
 * @author Q. T. Felix
 * @since 1.0.0
 */
public interface DigitalSignService extends KeyService {

    /**
     * 서명할 평문 데이터를 반환하는 메소드입니다.
     * 내부 배열 노출 방지를 위한 복사를 반환해야 합니다.
     *
     * @return 평문 데이터 바이트 배열
     */
    byte @NotNull [] getPlainBytes();

    /**
     * 생성된 서명 데이터를 반환하는 메소드입니다.
     * 내부 배열 노출 방지를 위한 복사를 반환해야 합니다.
     *
     * @return 서명 데이터 바이트 배열
     */
    byte[] getSignature();

    /**
     * 개인 키를 사용하여 평문 데이터에 전달받은 알고리즘으로 서명을 생성하는 메소드입니다.
     * <p>
     * 대용량 데이터의 경우 청크 단위로 처리할 수 있습니다.
     *
     * @param chunkSize 청크 크기 (0인 경우 청크 처리 안 함)
     * @return 생성된 서명 바이트 배열
     * @throws InvalidKeyException      잘못된 개인 키가 제공된 경우
     * @throws SignatureException       서명 생성 중 오류가 발생한 경우
     * @throws NoSuchAlgorithmException 전달받은 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException  지정된 공급자를 사용할 수 없는 경우
     */
    byte[] sign(@Nullable String provider, final @NotNull PrivateKey sk, int chunkSize)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException;

    default byte[] sign(final @NotNull PrivateKey sk, int chunkSize)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException{
        return sign(null, sk, chunkSize);
    }

    /**
     * 개인 키를 사용하여 평문 데이터에 전달받은 알고리즘으로 서명을 생성하는 메소드입니다.
     * <p>
     * 청크 처리를 사용하지 않는 버전의 서명 메소드입니다.
     *
     * @return 생성된 서명 바이트 배열
     * @throws InvalidKeyException      잘못된 개인 키가 제공된 경우
     * @throws SignatureException       서명 생성 중 오류가 발생한 경우
     * @throws NoSuchAlgorithmException 전달받은 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException  지정된 공급자를 사용할 수 없는 경우
     */
    default byte[] sign(final @NotNull PrivateKey sk)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        return sign(sk, 0);
    }

    /**
     * 공개 키를 사용하여 평문 데이터와 서명을 검증하는 메소드입니다.
     * <p>
     * 대용량 데이터의 경우 청크 단위로 처리할 수 있습니다.
     *
     * @param chunkSize 청크 크기 (0인 경우 청크 처리 안 함)
     * @return 서명이 유효한 경우 true, 그렇지 않으면 false
     * @throws NoSuchAlgorithmException 전달받은 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException  지정된 공급자를 사용할 수 없는 경우
     * @throws InvalidKeyException      잘못된 공개 키가 제공된 경우
     * @throws SignatureException       서명 검증 중 오류가 발생한 경우
     */
    boolean verify(@Nullable String provider, final @NotNull PublicKey pk, int chunkSize)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException;

    default boolean verify(final @NotNull PublicKey pk, int chunkSize)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException{
        return verify(null, pk, chunkSize);
    }

    /**
     * 공개 키를 사용하여 평문 데이터와 서명을 검증하는 메소드입니다.
     * <p>
     * 청크 처리를 사용하지 않는 버전의 검증 메소드입니다.
     *
     * @return 서명이 유효한 경우 true, 그렇지 않으면 false
     * @throws NoSuchAlgorithmException 전달받은 알고리즘을 사용할 수 없는 경우
     * @throws NoSuchProviderException  지정된 공급자를 사용할 수 없는 경우
     * @throws InvalidKeyException      잘못된 공개 키가 제공된 경우
     * @throws SignatureException       서명 검증 중 오류가 발생한 경우
     */
    default boolean verify(final @NotNull PublicKey pk)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return verify(pk, 0);
    }
}
